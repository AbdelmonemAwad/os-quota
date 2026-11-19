#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""The count, the cycles and the block (src/opnsense/scripts/quota: account.py, cycles.py, enforce.py,
hosts.py, settings.py, status.py), with stand-ins for what only a firewall has: pfctl - its states, the
table quota_over, its kills - the firewall's interfaces, and its host discovery. Every address a
documentation one.

What is checked:
  - settings read from a config.xml: the plugin's own, its rows, the alias and XGS: Settings' parts; a
    quota's host - an address, IPv6, a MAC in its forms - and what is refused;
  - the cycles: a day, a week from Monday, a month - February in a leap year, December into January - in
    UTC and through the clock changes of three zones, one changing at midnight;
  - the count: what a connection gained since the last read, one the last read did not see counted whole
    when it began since, one older not counted until it grows, up and down by which end made it, a tuple
    reused, a state of a connection ending first, a restart from the saved state, a second quota on the
    same host from its own start;
  - the minutes of use: the threshold, two reads in a minute, 0 for any byte;
  - the cycle turning: the counts from nothing, the host passing again; a clock set back not starting one;
  - the block: an address over its quota put in the table and taken out, never the firewall's own; a MAC's
    addresses - link-local and the firewall's left out; the cut done here without os-xgs-npu, left to
    XGS: Settings with it; the alias missing, not the plugin's or switched off: no table written;
  - off, a CARP backup, the interfaces unreadable: nothing counted, and off the table emptied;
  - a reset by hand; the command line - one read, --flush, --gone, --reset - its lock, its answer when a
    read stops; and the page's status.

    python3 tools/test-account.py"""
import calendar
import json
import os
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src', 'opnsense', 'scripts', 'quota'))
import account  # noqa: E402
import cycles  # noqa: E402
import enforce  # noqa: E402
import hosts  # noqa: E402
import settings  # noqa: E402
import status  # noqa: E402

failures = 0
checks = 0


def check(name, got, want):
    global failures, checks
    checks += 1
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


def zone(name):
    os.environ['TZ'] = name
    time.tzset()


def utc(*when):
    return calendar.timegm(when + (0,) * (6 - len(when)))


account.log = lambda message, error=False: LOGGED.append(message)
LOGGED = []
MB = 1000 * 1000


class FakePf(enforce.Pf):
    """pfctl: its states' text, the table quota_over (None: no such table), the states killed."""

    def __init__(self, text='', table=None, fail=()):
        self.text = text
        self.table = set(table) if table is not None else None
        self.killed = []
        self.calls = []
        self.fail = set(fail)
        super().__init__(run=self.fake)

    def fake(self, args):
        self.calls.append(' '.join(args))
        if args[:1] == ['-vvs']:
            return (1, 'pfctl: cannot read') if 'states' in self.fail else (0, self.text)
        if args[:2] == ['-t', 'quota_over']:
            verb = args[3]
            if verb == 'show':
                if self.table is None:
                    return 1, 'pfctl: Table does not exist.'
                return 0, ''.join('   %s\n' % a for a in sorted(self.table))
            if verb in self.fail:
                return 1, 'pfctl: refused'
            if verb == 'add':
                self.table = (self.table or set()) | set(args[4:])
            elif verb == 'delete':
                self.table = (self.table or set()) - set(args[4:])
            elif verb == 'kill':
                self.table = None
            return 0, ''
        if args[:2] == ['-k', 'id']:
            self.killed.append(args[3])
            return 0, ''
        if args == ['-v', '-s', 'Tables']:
            return 0, ('-pa----\tquota_over\n' if self.table is not None else '') + '-pa-r--\tbogons\n'
        return 1, 'pfctl: not this'


class FakeFw:
    def __init__(self, own=('192.0.2.1', '203.0.113.2', '2001:db8:1::1'), role=None, error=None, table=None,
                 project=False):
        self.own, self.role, self.error, self.table, self.project = set(own), role, error, table or {}, project
        self.asked = 0

    def interfaces(self):
        return set(self.own), self.role, self.error

    def neighbours(self):
        self.asked += 1
        return {k: list(v) for k, v in self.table.items()}, 'hostwatch', None


def quota(uuid, host, volume=None, minutes=None, cycle='day', enabled=True, description=''):
    return {'uuid': uuid, 'enabled': enabled, 'host_text': host, 'host': settings.host(host),
            'volume': volume, 'minutes': minutes, 'cycle': cycle, 'description': description}


def conf(*quotas, enabled=True, minute_kb=100):
    return {'read': True, 'enabled': enabled, 'minute_bytes': minute_kb * 1000, 'quotas': list(quotas),
            'xgs': False, 'cut_lists': [], 'count_to_pf': None, 'cut_in_hardware': None, 'cut_added': []}


OURS = {'uuid': 'a0000000-0000-4000-8000-000000000001', 'enabled': True, 'type': 'external', 'ours': True}


def pair(sport, up, down, age, ids, host='192.0.2.10', server='198.51.100.7', dport=443, nat=True):
    """A routed connection's two states, as pf prints them: in on the LAN, out on the WAN through NAT."""
    out = ['all tcp %s:%d <- %s:%d       ESTABLISHED:ESTABLISHED' % (server, dport, host, sport),
           '   age %s, expires in 23:59:56, 10:10 pkts, %d:%d bytes, rule 117' % (hms(age), up, down),
           '   id: %s creatorid: 44128282' % ids[0]]
    if nat:
        out += ['all tcp 203.0.113.2:%d (%s:%d) -> %s:%d       ESTABLISHED:ESTABLISHED' % (sport + 20000, host, sport, server, dport),
                '   age %s, expires in 23:59:56, 10:10 pkts, %d:%d bytes, rule 108' % (hms(age), up, down),
                '   id: %s creatorid: 44128282' % ids[1]]
    return '\n'.join(out) + '\n'


def inbound(sport, up, down, age, ident, sender='198.51.100.8', host='192.0.2.11'):
    """A connection made from outside to an inside host (its state on the way in)."""
    return ('all tcp %s:80 (203.0.113.2:8080) <- %s:%d       ESTABLISHED:ESTABLISHED\n'
            '   age %s, expires in 23:59:59, 3:4 pkts, %d:%d bytes, rule 130\n'
            '   id: %s creatorid: 44128282\n' % (host, sender, sport, hms(age), up, down, ident))


def hms(seconds):
    return '%02d:%02d:%02d' % (seconds // 3600, seconds // 60 % 60, seconds % 60)


def q_state(state, uuid):
    return state['quotas'][uuid]


U1 = '11111111-1111-4111-8111-111111111111'
U2 = '22222222-2222-4222-8222-222222222222'
U3 = '33333333-3333-4333-8333-333333333333'

zone('UTC')

# --- settings
with tempfile.TemporaryDirectory() as tmp:
    config = os.path.join(tmp, 'config.xml')
    with open(config, 'w', encoding='utf-8') as handle:
        handle.write('''<?xml version="1.0"?>
<opnsense><OPNsense>
<Quota version="1.0.0"><general><enabled>1</enabled><minute_threshold>250</minute_threshold><cut_added>a1</cut_added></general>
<quotas>
<quota uuid="%s"><enabled>1</enabled><host>192.0.2.10</host><volume>5000</volume><minutes></minutes><cycle>month</cycle><description>Desk</description></quota>
<quota uuid="%s"><enabled>0</enabled><host>02-00-00-AA-BB-CC</host><volume></volume><minutes>120</minutes><cycle>week</cycle><description/></quota>
<quota uuid="%s"><enabled>1</enabled><host>2001:DB8:1::0010</host><volume>1</volume><minutes>1</minutes><cycle>hourly</cycle><description/></quota>
</quotas></Quota>
<Firewall><Alias><aliases><alias uuid="a1"><enabled>1</enabled><name>quota_over</name><type>external</type><description>Quotas: hosts over their quota</description></alias>
<alias uuid="a2"><enabled>1</enabled><name>mine</name><type>host</type><description>x</description></alias></aliases></Alias></Firewall>
<XGS><general><cut_lists>o1,a1</cut_lists><count_to_pf>0</count_to_pf></general></XGS>
</OPNsense></opnsense>
''' % (U1, U2, U3))
    got = settings.read(config)
    check('settings: on, the minute threshold in bytes, the record of the cut list',
          (got['read'], got['enabled'], got['minute_bytes'], got['cut_added']), (True, True, 250000, ['a1']))
    check('settings: the rows - volume in bytes, minutes, cycle, a MAC in its one form, IPv6 as pf prints it',
          [(q['uuid'], q['enabled'], q['host'], q['volume'], q['minutes'], q['cycle']) for q in got['quotas']],
          [(U1, True, ('address', '192.0.2.10'), 5000 * MB, None, 'month'),
           (U2, False, ('mac', '02:00:00:aa:bb:cc'), None, 120, 'week'),
           (U3, True, ('address', '2001:db8:1::10'), MB, 1, 'day')])
    check('settings: XGS: Settings\' cut list and its hardware counts off', (got['xgs'], got['cut_lists'], got['count_to_pf']),
          (True, ['o1', 'a1'], False))
    check('the alias: the plugin\'s, by its description', settings.alias(config),
          {'uuid': 'a1', 'enabled': True, 'type': 'external', 'ours': True})
    check('no config.xml: the defaults, off, read False',
          (settings.read(os.path.join(tmp, 'none.xml'))['read'], settings.read(os.path.join(tmp, 'none.xml'))['enabled'],
           settings.alias(os.path.join(tmp, 'none.xml'))), (False, False, None))
    with open(config, 'w', encoding='utf-8') as handle:
        handle.write('<opnsense><OPNsense><Firewall><Alias><aliases><alias uuid="b1"><name>quota_over</name><type>host</type>'
                     '<description>my list</description></alias></aliases></Alias></Firewall></OPNsense></opnsense>')
    check('an alias of that name that is the owner\'s: not the plugin\'s', settings.alias(config)['ours'], False)
    check('nothing of the plugin\'s in config.xml: off, threshold 100 KB, no row, no XGS',
          (settings.read(config)['enabled'], settings.read(config)['minute_bytes'], settings.read(config)['quotas'],
           settings.read(config)['xgs']), (False, 100000, [], False))

hosts_ok = [('192.0.2.10', ('address', '192.0.2.10')), ('2001:DB8::1', ('address', '2001:db8::1')),
            ('02:00:00:aa:bb:cc', ('mac', '02:00:00:aa:bb:cc')), ('0200.00aa.bbcc', None),
            ('020000AABBCC', ('mac', '02:00:00:aa:bb:cc')), ('de-ad-be-ef-00-01', ('mac', 'de:ad:be:ef:00:01'))]
hosts_no = ['0.0.0.0', '0.1.2.3', '127.0.0.1', '169.254.1.1', '224.0.0.5', '255.255.255.255', '::', '::1', 'fe80::1',
            'ff02::1', '00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff', '01:00:5e:00:00:01', '192.0.2.0/24', 'host.example', '']
check('a host: an address or a MAC in its forms', [settings.host(t) for t, _ in hosts_ok], [w for _, w in hosts_ok])
check('not a host: unspecified, this network, loopback, link-local, multicast, broadcast, a network, a name',
      [settings.host(t) for t in hosts_no], [None] * len(hosts_no))

# --- cycles
now = utc(2026, 11, 20, 10, 30)                      # a Friday
check('a day: from 00:00 to the next', cycles.current('day', now), (utc(2026, 11, 20), utc(2026, 11, 21)))
check('a week: from Monday', cycles.current('week', now), (utc(2026, 11, 16), utc(2026, 11, 23)))
check('a month: from the 1st', cycles.current('month', now), (utc(2026, 11, 1), utc(2026, 12, 1)))
check('a Monday at 00:00 is its own week\'s start', cycles.start('week', utc(2026, 11, 16)), utc(2026, 11, 16))
check('a second before: the week before', cycles.start('week', utc(2026, 11, 16) - 1), utc(2026, 11, 9))
check('February in a leap year', cycles.current('month', utc(2028, 2, 29, 23, 59)), (utc(2028, 2, 1), utc(2028, 3, 1)))
check('December into January', cycles.current('month', utc(2026, 12, 31, 12)), (utc(2026, 12, 1), utc(2027, 1, 1)))
for name, days in (('Europe/Berlin', [(2026, 3, 29), (2026, 10, 25)]), ('America/New_York', [(2026, 3, 8), (2026, 11, 1)]),
                   ('America/Santiago', [(2026, 9, 6), (2026, 4, 5)])):
    zone(name)
    bad = []
    for day in days:
        base = utc(*day) - 2 * 86400
        for step in range(0, 5 * 86400, 1800):
            t = base + step
            for kind in cycles.KINDS:
                begin, finish = cycles.current(kind, t)
                lt = time.localtime(begin)
                if not begin <= t < finish or (kind == 'day' and lt.tm_mday != time.localtime(t).tm_mday):
                    bad.append((kind, t))
    lengths = sorted({cycles.current('day', utc(*d) + 43200)[1] - cycles.current('day', utc(*d) + 43200)[0]
                      for d in days})
    check('%s: every moment of the days around its clock changes in its own day, week and month; those days %s hours'
          % (name, ' and '.join(str(n // 3600) for n in lengths)), bad, [])
zone('UTC')

# --- the count
t0 = utc(2026, 11, 20, 10, 0, 5)
state = {}
q1 = quota(U1, '192.0.2.10', volume=10 * MB)
pf = FakePf(pair(50123, 4000, 9000, 600, ['0001', '0002']), table=set())
fw = FakeFw()
answer = account.tick(state, conf(q1), OURS, pf, fw, t0)
check('the first read: a connection there before the quota counts nothing yet', (q_state(state, U1)['up'],
                                                                                    q_state(state, U1)['down'], answer['status']),
      (0, 0, 'ok'))
check('the first read: the connection kept for the next, once, its counts as pf has them',
      state['conns'], {'tcp 192.0.2.10:50123 198.51.100.7:443': {'ids': ['0001/44128282', '0002/44128282'], 'up': 4000,
                                                                   'down': 9000}})
pf.text = pair(50123, 5000, 109000, 660, ['0001', '0002']) + pair(50200, 700, 1300, 20, ['0003', '0004'])
account.tick(state, conf(q1), OURS, pf, fw, t0 + 60)
check('the next read: what it gained (1,000 up, 100,000 down), and a connection begun since counted whole',
      (q_state(state, U1)['up'], q_state(state, U1)['down']), (1000 + 700, 100000 + 1300))
# the WAN state of the first connection ends first, the LAN one with a smaller count than kept
pf.text = (pair(50123, 4500, 100000, 720, ['0001', '0002'], nat=False) + pair(50200, 700, 1300, 80, ['0003', '0004']))
account.tick(state, conf(q1), OURS, pf, fw, t0 + 120)
check('a state of a connection ending first, the other behind it: nothing taken back, nothing counted again',
      (q_state(state, U1)['up'], q_state(state, U1)['down'],
       state['conns']['tcp 192.0.2.10:50123 198.51.100.7:443']['down']), (1700, 101300, 109000))
pf.text = pair(50123, 5000, 110000, 780, ['0001', '0002'], nat=False)
account.tick(state, conf(q1), OURS, pf, fw, t0 + 180)
check('... and when it catches up, only past the largest count kept', (q_state(state, U1)['up'], q_state(state, U1)['down']),
      (1700, 102300))
# the same tuple, a new connection: new ids
pf.text = pair(50123, 300, 600, 10, ['0009', '000a'])
account.tick(state, conf(q1), OURS, pf, fw, t0 + 240)
check('a connection on the same ends with new ids: a new one, counted whole', (q_state(state, U1)['up'], q_state(state, U1)['down']),
      (2000, 102900))
# a restart: the state saved and read back
with tempfile.TemporaryDirectory() as tmp:
    path = os.path.join(tmp, 'state.json')
    account.save(state, path)
    state = account.load(path)
pf.text = pair(50123, 300, 600, 70, ['0009', '000a'])
account.tick(state, conf(q1), OURS, pf, fw, t0 + 300)
check('after a restart from the saved state: nothing counted twice', (q_state(state, U1)['up'], q_state(state, U1)['down']),
      (2000, 102900))

# the other end made it: up and down the other way
state = {}
q2 = quota(U2, '192.0.2.11', volume=10 * MB)
pf = FakePf('', table=set())
account.tick(state, conf(q2), OURS, pf, fw, t0)
pf.text = inbound(40000, 25000, 600000, 30, '0101')
account.tick(state, conf(q2), OURS, pf, fw, t0 + 60)
check('a connection made to the host from outside: up is what it sent back', (q_state(state, U2)['up'], q_state(state, U2)['down']),
      (600000, 25000))

# a second quota on the same host, made later: from its own start
state = {}
pf = FakePf(pair(50123, 1000, 1000, 5, ['0001', '0002']), table=set())
account.tick(state, conf(q1), OURS, pf, fw, t0)
pf.text = pair(50123, 3000, 3000, 65, ['0001', '0002'])
q3 = quota(U3, '192.0.2.10', minutes=30)
account.tick(state, conf(q1, q3), OURS, pf, fw, t0 + 60)
pf.text = pair(50123, 4000, 4000, 125, ['0001', '0002'])
account.tick(state, conf(q1, q3), OURS, pf, fw, t0 + 120)
check('a second quota on the same host: the first counts all, the second from the read that found it',
      (q_state(state, U1)['up'] + q_state(state, U1)['down'], q_state(state, U3)['up'] + q_state(state, U3)['down']),
      (6000, 2000))
check('quotas no longer in the settings are forgotten', (account.tick(state, conf(q3), OURS, pf, fw, t0 + 180)['status'],
                                                         sorted(state['quotas'])), ('ok', [U3]))
check('the host given another address: its count starts anew',
      (account.tick(state, conf(quota(U3, '192.0.2.99', minutes=30)), OURS, pf, fw, t0 + 240)['status'],
       q_state(state, U3)['host'], q_state(state, U3)['up']), ('ok', 'address 192.0.2.99', 0))

# --- minutes of use
state = {}
qt = quota(U1, '192.0.2.10', minutes=3)
base = utc(2026, 11, 20, 12, 0, 1)
pf = FakePf(pair(50123, 0, 0, 1, ['0001', '0002']), table=set())
account.tick(state, conf(qt), OURS, pf, fw, base)
seen = []
for n, (up, down) in enumerate([(10000, 50000), (10000, 200000), (20000, 460000), (20000, 460001)], 1):
    pf.text = pair(50123, up, down, 1 + 60 * n, ['0001', '0002'])
    account.tick(state, conf(qt), OURS, pf, fw, base + 60 * n)
    seen.append(q_state(state, U1)['minutes'])
check('minutes of use: 60 KB in a minute is none, 150 KB one, 270 KB one, 1 byte none', seen, [0, 1, 2, 2])
pf.text = pair(50123, 20000, 510001, 261, ['0001', '0002'])
account.tick(state, conf(qt), OURS, pf, fw, base + 240 + 20)
check('a second read in the same minute adds to that minute: 50 KB more makes 50 KB and 1 byte - no minute yet',
      q_state(state, U1)['minutes'], 2)
pf.text = pair(50123, 20000, 580001, 281, ['0001', '0002'])
account.tick(state, conf(qt), OURS, pf, fw, base + 240 + 40)
check('... and 70 KB more in it passes 100 KB: one minute, and the third reaches the quota',
      (q_state(state, U1)['minutes'], q_state(state, U1)['over'], q_state(state, U1)['why']), (3, True, ['time']))
state = {}
pf = FakePf(pair(50123, 0, 0, 1, ['0001', '0002']), table=set())
account.tick(state, conf(qt, minute_kb=0), OURS, pf, fw, base)
pf.text = pair(50123, 0, 1, 61, ['0001', '0002'])
account.tick(state, conf(qt, minute_kb=0), OURS, pf, fw, base + 60)
check('a threshold of 0: one byte makes a minute of use', q_state(state, U1)['minutes'], 1)

# --- the block
state = {}
LOGGED.clear()
qv = quota(U1, '192.0.2.10', volume=MB, description='Desk')
traffic = pair(50123, 0, 0, 1, ['0001', '0002']) + inbound(40000, 5, 5, 1, '0101', host='192.0.2.10')
pf = FakePf(traffic, table=set())
account.tick(state, conf(qv), OURS, pf, fw, t0)
pf.text = pair(50123, 300000, 700000, 61, ['0001', '0002']) + inbound(40000, 5, 5, 61, '0101', host='192.0.2.10')
answer = account.tick(state, conf(qv), OURS, pf, fw, t0 + 60)
check('a host reaching its volume: over, its address in the table', (q_state(state, U1)['over'], q_state(state, U1)['why'],
                                                                      pf.table, answer['added']),
      (True, ['volume'], {'192.0.2.10'}, 1))
check('without os-xgs-npu its open connections cut here, read again after the table had it: every state of it',
      sorted(pf.killed), ['0001/44128282', '0002/44128282', '0101/44128282'])
check('the system log says it went over, once', [m for m in LOGGED if 'over its' in m],
      ['Desk: over its volume quota - 1 address(es) blocked until its cycle starts again'])
pf.killed = []
account.tick(state, conf(qv), OURS, pf, fw, t0 + 120)
check('the next minute: still in the table, nothing cut again', (pf.table, pf.killed), ({'192.0.2.10'}, []))
pf.table = set()
account.tick(state, conf(qv), OURS, pf, fw, t0 + 180)
check('the table emptied by hand (or a boot): filled again at the next read, and cut again', (pf.table, len(pf.killed)),
      ({'192.0.2.10'}, 3))
# with os-xgs-npu
state2 = json.loads(json.dumps(state))
pf2 = FakePf(pf.text, table=set())
account.tick(state2, conf(qv), OURS, pf2, FakeFw(project=True), t0 + 240)
check('with os-xgs-npu: in the table, nothing cut here - XGS: Settings\' cut list does it', (pf2.table, pf2.killed),
      ({'192.0.2.10'}, []))
# a new cycle
LOGGED.clear()
tomorrow = utc(2026, 11, 21, 0, 0, 30)
account.tick(state, conf(qv), OURS, pf, fw, tomorrow)
check('the cycle turns: the counts from nothing, the host out of the table, said in the log',
      (q_state(state, U1)['up'], q_state(state, U1)['over'], pf.table, [m for m in LOGGED if 'new cycle' in m]),
      (0, False, set(), ['Desk: a new cycle - passes again']))
state['quotas'][U1].update(up=MB, over=True, why=['volume'])
account.tick(state, conf(qv), OURS, pf, fw, tomorrow - 3600)
check('a clock set back an hour: the cycle does not start again', (q_state(state, U1)['start'], q_state(state, U1)['up']),
      (utc(2026, 11, 21), MB))
pf.text = pair(50123, 400000, 700000, 7000, ['0001', '0002']) + inbound(40000, 5, 5, 7000, '0101', host='192.0.2.10')
account.tick(state, conf(qv), OURS, pf, fw, tomorrow - 3600 + 60)
check('... and the count goes on from there, not an hour later', q_state(state, U1)['up'], MB + 100000)
state['quotas'][U1]['since'] = tomorrow + 600       # the quota started by a clock that was ahead
pf.text = pair(50123, 500000, 700000, 7060, ['0001', '0002']) + inbound(40000, 5, 5, 7060, '0101', host='192.0.2.10')
account.tick(state, conf(qv), OURS, pf, fw, tomorrow - 3600 + 120)
pf.text = pair(50123, 600000, 700000, 7120, ['0001', '0002']) + inbound(40000, 5, 5, 7120, '0101', host='192.0.2.10')
account.tick(state, conf(qv), OURS, pf, fw, tomorrow - 3600 + 180)
check('a quota started by a clock since set back: started again now, then counted - not stopped until the clock came round',
      (q_state(state, U1)['since'], q_state(state, U1)['up']), (tomorrow - 3600 + 120, MB + 200000))

# never the firewall's own address
state = {}
qo = quota(U1, '192.0.2.1', volume=1)
pf = FakePf(pair(50123, 0, 0, 1, ['0001', '0002'], host='192.0.2.1'), table=set())
account.tick(state, conf(qo), OURS, pf, fw, t0)
state['quotas'][U1].update(up=10, over=True)
account.tick(state, conf(qo), OURS, pf, fw, t0 + 60)
check('a quota naming the firewall\'s own address: never in the table, marked', (pf.table, q_state(state, U1)['own'],
                                                                                  q_state(state, U1)['addresses']),
      (set(), True, []))

# a MAC
state = {}
qm = quota(U1, '02:00:00:aa:bb:cc', volume=MB)
macfw = FakeFw(table={'02:00:00:aa:bb:cc': ['192.0.2.10', '2001:db8:1::10', 'fe80::1', '192.0.2.1'],
                      '02:00:00:dd:ee:ff': ['192.0.2.11']})
pf = FakePf(pair(50123, 0, 0, 1, ['0001', '0002']) + pair(50000, 0, 0, 1, ['0005', '0006'], host='192.0.2.11'), table=set())
account.tick(state, conf(qm), OURS, pf, macfw, t0)
check('a MAC: its addresses from host discovery, link-local and the firewall\'s own left out',
      q_state(state, U1)['addresses'], ['192.0.2.10', '2001:db8:1::10'])
pf.text = (pair(50123, 500000, 600000, 61, ['0001', '0002']) +
           pair(50000, 900000, 900000, 61, ['0005', '0006'], host='192.0.2.11'))
account.tick(state, conf(qm), OURS, pf, macfw, t0 + 60)
check('a MAC over its quota: its addresses blocked, another device\'s traffic not counted to it',
      (q_state(state, U1)['up'] + q_state(state, U1)['down'], sorted(pf.table)), (1100000, ['192.0.2.10', '2001:db8:1::10']))
macfw.table['02:00:00:aa:bb:cc'] = ['192.0.2.10', '2001:db8:1::77']
account.tick(state, conf(qm), OURS, pf, macfw, t0 + 120)
check('a new IPv6 address of the MAC: blocked at the next read, the old one taken out',
      sorted(pf.table), ['192.0.2.10', '2001:db8:1::77'])
check('host discovery asked only for MACs', (FakeFw().asked, macfw.asked), (0, 3))

# the alias
for alias, what in ((None, 'missing'), (dict(OURS, ours=False), 'the owner\'s'), (dict(OURS, enabled=False), 'switched off'),
                    (dict(OURS, type='host'), 'not External')):
    state = {}
    pf = FakePf(pair(50123, 0, 0, 1, ['0001', '0002']), table={'198.51.100.200'})
    account.tick(state, conf(qv), alias, pf, fw, t0)
    pf.text = pair(50123, 2 * MB, 0, 61, ['0001', '0002'])
    account.tick(state, conf(qv), alias, pf, fw, t0 + 60)
    check('the alias %s: over, but no table written, nothing cut, the error said' % what,
          (q_state(state, U1)['over'], pf.table, pf.killed, bool(state.get('error'))), (True, {'198.51.100.200'}, [], True))
state = {}
pf = FakePf(pair(50123, 0, 0, 1, ['0001', '0002']), table=set(), fail=('add',))
account.tick(state, conf(qv), OURS, pf, fw, t0)
pf.text = pair(50123, 2 * MB, 0, 61, ['0001', '0002'])
answer = account.tick(state, conf(qv), OURS, pf, fw, t0 + 60)
check('pfctl refusing the table: said as the last error, the answer failed', (answer['status'], 'refused' in
                                                                              state['error']['message']), ('failed', True))
first_logged = state['error']['logged']
account.tick(state, conf(qv), OURS, pf, fw, t0 + 120)
check('the same fault a minute later: the last error\'s time moves, the log is not written again',
      (state['error']['at'], state['error']['logged']), (t0 + 120, first_logged))

# --- off, CARP backup, the interfaces unreadable, states unreadable
state = {}
pf = FakePf(pair(50123, 0, 0, 1, ['0001', '0002']), table=set())
account.tick(state, conf(qv), OURS, pf, fw, t0)
pf.text = pair(50123, 2 * MB, 0, 61, ['0001', '0002'])
account.tick(state, conf(qv), OURS, pf, fw, t0 + 60)
answer = account.tick(state, conf(qv, enabled=False), OURS, pf, fw, t0 + 120)
check('off: the table emptied, the connections forgotten, the counts kept, paused',
      (answer['status'], pf.table, state['conns'], q_state(state, U1)['up'], q_state(state, U1)['since']),
      ('off', set(), {}, 2 * MB, None))
calls = len(pf.calls)
account.tick(state, conf(qv, enabled=False), OURS, pf, fw, t0 + 180)
check('off, the next minute: pf not asked at all', len(pf.calls), calls)
pf.text = pair(50123, 3 * MB, 0, 241, ['0001', '0002'])
account.tick(state, conf(qv), OURS, pf, fw, t0 + 240)
check('on again: what passed while off not counted, the host blocked again by the counts kept',
      (q_state(state, U1)['up'], pf.table), (2 * MB, {'192.0.2.10'}))
state = {}
pf = FakePf(pair(50123, 0, 0, 1, ['0001', '0002']), table=set())
answer = account.tick(state, conf(qv), OURS, pf, FakeFw(role='backup'), t0)
check('a CARP backup: nothing read, nothing counted', (answer['status'], pf.calls, state.get('role')), ('backup', [], 'backup'))
answer = account.tick(state, conf(qv), OURS, pf, FakeFw(error='ifconfig exited 1'), t0)
check('the interfaces unreadable: nothing read or changed, said', (answer['status'], pf.calls,
                                                                  'own addresses' in state['error']['message']),
      ('failed', [], True))
state = {}
pf = FakePf('', table=set(), fail=('states',))
answer = account.tick(state, conf(qv), OURS, pf, fw, t0)
check('pf\'s states unreadable: said, nothing counted', (answer['status'], 'states could not be read' in state['error']['message'],
                                                        q_state(state, U1)['up']), ('failed', True, 0))
state = {}
pf = FakePf('', table=set())
account.tick(state, conf(quota(U1, '02:00:00:00:00:99', volume=1)), OURS, pf, FakeFw(), t0)
check('no host has an address to watch: pf\'s states not read', [c for c in pf.calls if c.startswith('-vvs')], [])

# --- reset
state = {}
pf = FakePf(pair(50123, 0, 0, 1, ['0001', '0002']), table=set())
account.tick(state, conf(qv), OURS, pf, fw, t0)
pf.text = pair(50123, 2 * MB, 0, 61, ['0001', '0002'])
account.tick(state, conf(qv), OURS, pf, fw, t0 + 60)
done = account.reset(state, U1, conf(qv))
account.tick(state, conf(qv), OURS, pf, fw, t0 + 70)
check('a reset by hand: the count from nothing, the host out of the table, what it carried before not counted again',
      (done, q_state(state, U1)['up'], pf.table), ([U1], 0, set()))
check('reset all', account.reset(state, 'all', conf(qv, quota(U2, '192.0.2.11', volume=1))), [U1, U2])

# --- the command line
with tempfile.TemporaryDirectory() as tmp:
    path = os.path.join(tmp, 'state.json')
    lock = os.path.join(tmp, 'account.lock')
    config = os.path.join(tmp, 'config.xml')

    def write_config(enabled='1', alias=True):
        with open(config, 'w', encoding='utf-8') as handle:
            handle.write('<opnsense><OPNsense><Quota><general><enabled>%s</enabled></general><quotas><quota uuid="%s">'
                         '<enabled>1</enabled><host>192.0.2.10</host><volume>1</volume><cycle>day</cycle></quota></quotas>'
                         '</Quota><Firewall><Alias><aliases>%s</aliases></Alias></Firewall></OPNsense></opnsense>'
                         % (enabled, U1, '<alias uuid="a1"><enabled>1</enabled><name>quota_over</name><type>external</type>'
                                         '<description>Quotas: hosts over their quota</description></alias>' if alias else ''))

    def cli(*args, pf=None, fw=None):
        import io
        import contextlib
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = account.main(['account.py'] + list(args), pf=pf or FakePf('', table=set()), fw=fw or FakeFw(),
                                config=config, path=path, lock=lock)
        return code, json.loads(out.getvalue())

    write_config()
    pf = FakePf(pair(50123, 0, 0, 1, ['0001', '0002']), table=set())
    code, out = cli(pf=pf)
    check('account.py: one read, its JSON answer, 0', (code, out['status'], os.path.exists(path)), (0, 'ok', True))
    pf.text = pair(50123, 2 * MB, 0, 61, ['0001', '0002'])
    code, out = cli(pf=pf)
    check('account.py: the host over its quota, in the table', (out['over'], pf.table), (1, {'192.0.2.10'}))
    code, out = cli('--reset', 'not-an-id', pf=pf)
    check('account.py --reset with no quota\'s id: refused', (code, out['status']), (0, 'failed'))
    code, out = cli('--reset', U1, pf=pf)
    check('account.py --reset UUID: reset, then a read - the host out of the table', (out['reset'], pf.table), ([U1], set()))
    code, out = cli('--flush', pf=pf)
    check('account.py --flush: the table emptied, the counting paused', (out['status'], account.load(path)['conns']),
          ('ok', {}))
    code, out = cli('--gone', pf=pf)
    check('account.py --gone with the alias there: the table kept', (out['killed'], pf.table), (False, set()))
    write_config(alias=False)
    code, out = cli('--gone', pf=pf)
    check('account.py --gone with the alias gone: the table killed', (out['killed'], pf.table), (True, None))
    with open(config, 'w', encoding='utf-8') as handle:
        handle.write('<opnsense>')
    pf = FakePf('', table=set())
    code, out = cli('--gone', pf=pf)
    check('account.py --gone, config.xml unreadable: the table not killed', (out['killed'], pf.table), (False, set()))
    code, out = cli(pf=pf)
    check('account.py, config.xml unreadable: failed, said, nothing changed', (code, out['status'], pf.calls),
          (0, 'failed', []))
    write_config()

    class Broken(FakeFw):
        def interfaces(self):
            raise RuntimeError('a stand-in that fails')

    code, out = cli(pf=FakePf('', table=set()), fw=Broken())
    check('a read that stops: caught, said, 0', (code, out['status'], 'stopped' in account.load(path)['error']['message']),
          (0, 'failed', True))
    write_config(enabled='0')
    cli()
    before = os.stat(path).st_mtime_ns
    time.sleep(0.05)
    cli()
    check('off, a minute\'s run writes nothing', os.stat(path).st_mtime_ns, before)
    import fcntl
    with open(lock, 'a') as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        account.WAIT = 0.2
        code, out = cli()
        account.WAIT = 50
    check('another read still running: busy, nothing done', (code, out['status']), (0, 'busy'))

# --- hosts.py on FreeBSD's own output
IFCONFIG = '''igb0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
\toptions=4e527bb<RXCSUM,TXCSUM>
\tinet 203.0.113.2 netmask 0xffffff00 broadcast 203.0.113.255
\tinet6 fe80::1%igb0 prefixlen 64 scopeid 0x1
\tinet 203.0.113.9 netmask 0xffffffff broadcast 203.0.113.9 vhid 1
\tcarp: BACKUP vhid 1 advbase 1 advskew 100
igb1: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
\tinet 192.0.2.1/24 broadcast 192.0.2.255
\tinet6 2001:db8:1::1 prefixlen 64
\tcarp: MASTER vhid 2 advbase 1 advskew 0
lo0: flags=1008049<UP,LOOPBACK,RUNNING,MULTICAST,LOWER_UP> metric 0 mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
'''
check('ifconfig -a: the firewall\'s own addresses, every form', hosts.own(IFCONFIG),
      {'203.0.113.2', 'fe80::1', '203.0.113.9', '192.0.2.1', '2001:db8:1::1', '127.0.0.1'})
check('CARP: one master is master; all backup is backup; none is None',
      (hosts.carp_role(IFCONFIG), hosts.carp_role(IFCONFIG.replace('MASTER', 'BACKUP')), hosts.carp_role('igb0: flags=1\n')),
      ('master', 'backup', None))
LIST = json.dumps({'source': 'discovery', 'rows': [['igb1', '02:00:00:dd:ee:ff', '192.0.2.10'],
                                                   ['igb1', '02:00:00:aa:bb:cc', '2001:db8:1::10'],
                                                   ['igb1', '02:00:00:aa:bb:cc', '192.0.2.10'],
                                                   ['igb1', '02:00:00:AA:BB:CC', 'fe80::10%igb1'], ['bad'],
                                                   ['igb1', 'not a mac', '192.0.2.30']]})
check('host discovery: newest first, so an address another device took since is that device\'s',
      hosts.list_hosts(LIST), {'02:00:00:dd:ee:ff': ['192.0.2.10'], '02:00:00:aa:bb:cc': ['2001:db8:1::10', 'fe80::10']})
check('host discovery\'s answer unreadable: None', (hosts.list_hosts('not json'), hosts.list_hosts('[]')), (None, None))
ARP = ('? (192.0.2.10) at 02:00:00:aa:bb:cc on igb1 expires in 1185 seconds [ethernet]\n'
       '? (192.0.2.11) at (incomplete) on igb1 expired [ethernet]\n'
       '? (192.0.2.1) at 02:00:00:00:00:01 on igb1 permanent [ethernet]\n')
NDP = ('Neighbor                             Linklayer Address  Netif Expire    1s 5s\n'
       '2001:db8:1::10                       02:00:00:aa:bb:cc   igb1 23h59m58s S R\n'
       'fe80::10%igb1                        02:00:00:aa:bb:cc   igb1 23h59m58s S R\n'
       '2001:db8:1::99                       (incomplete)        igb1 expired   N\n')
check('arp -an and ndp -an: each MAC\'s addresses, no incomplete entry',
      (hosts.arp(ARP), hosts.ndp(NDP)),
      ({'02:00:00:aa:bb:cc': ['192.0.2.10'], '02:00:00:00:00:01': ['192.0.2.1']},
       {'02:00:00:aa:bb:cc': ['2001:db8:1::10', 'fe80::10']}))
check('a MAC\'s usable addresses: not link-local, not the firewall\'s own, only the MACs asked',
      hosts.addresses_of({'02:00:00:aa:bb:cc', '02:00:00:00:00:77'}, {'02:00:00:aa:bb:cc': ['192.0.2.10', 'fe80::10', '192.0.2.1'],
                                                                     '02:00:00:00:00:01': ['192.0.2.50']}, {'192.0.2.1'}),
      {'02:00:00:aa:bb:cc': {'192.0.2.10'}, '02:00:00:00:00:77': set()})

# --- the page's status
with tempfile.TemporaryDirectory() as tmp:
    config = os.path.join(tmp, 'config.xml')
    path = os.path.join(tmp, 'state.json')
    rows = ''.join('<quota uuid="%s"><enabled>%s</enabled><host>%s</host><volume>%s</volume><minutes>%s</minutes>'
                   '<cycle>day</cycle><description>%s</description></quota>' % r for r in (
                       (U1, '1', '192.0.2.10', '10', '', 'over'), (U2, '1', '192.0.2.11', '10', '', 'near'),
                       (U3, '1', '192.0.2.12', '10', '100', 'under'), ('44444444-4444-4444-8444-444444444444', '0', '192.0.2.13',
                                                                      '10', '', 'off'),
                       ('55555555-5555-4555-8555-555555555555', '1', '192.0.2.1', '10', '', 'own'),
                       ('66666666-6666-4666-8666-666666666666', '1', '192.0.2.16', '10', '', 'waiting')))
    with open(config, 'w', encoding='utf-8') as handle:
        handle.write('<opnsense><OPNsense><Quota><general><enabled>1</enabled></general><quotas>%s</quotas></Quota>'
                     '<Firewall><Alias><aliases><alias uuid="a1"><enabled>1</enabled><name>quota_over</name><type>external</type>'
                     '<description>Quotas: hosts over their quota</description></alias></aliases></Alias></Firewall>'
                     '<XGS><general><cut_lists>o1,a1</cut_lists></general></XGS></OPNsense></opnsense>' % rows)
    account.save({'quotas': {
        U1: {'since': 1, 'up': 6 * MB, 'down': 5 * MB, 'over': True, 'over_at': 100, 'why': ['volume'], 'start': 1, 'end': 2,
             'addresses': ['192.0.2.10']},
        U2: {'since': 1, 'up': 4 * MB, 'down': 4 * MB, 'over': False, 'minutes': 0},
        U3: {'since': 1, 'up': 1 * MB, 'down': 0, 'over': False, 'minutes': 50},
        '55555555-5555-4555-8555-555555555555': {'since': 1, 'own': True},
        '66666666-6666-4666-8666-666666666666': {'since': None}},
        'role': 'master', 'last': {'at': 5, 'connections': 3}, 'error': None}, path)
    got = status.report(config=config, path=path, pf=FakePf('', table={'192.0.2.10'}), project=tmp)
    check('status: each quota\'s state', [r['state'] for r in got['quotas']],
          ['over', 'near', 'under', 'off', 'own', 'waiting'])
    check('status: the counts for the cards - over, near, what the quotas on used',
          got['counts'], {'quotas': 5, 'over': 1, 'near': 1, 'used': 20 * MB})
    check('status: the share of the larger limit, the reason, the table, the cut list, os-xgs-npu there',
          (got['quotas'][1]['percent'], got['quotas'][2]['percent'], got['quotas'][0]['why'], got['table'],
           got['cut_listed'], got['project'], got['alias']),
          (80.0, 50.0, ['volume'], 1, True, True, {'ours': True, 'enabled': True, 'external': True}))
    check('status: every key the page reads', sorted(got),
          sorted(['alias', 'count_to_pf', 'counts', 'cut_in_hardware', 'cut_listed', 'enabled', 'error', 'last',
                  'minute_bytes', 'near_percent', 'project', 'quotas', 'read', 'role', 'table', 'xgs']))
    check('status of a row: every key the grid reads', sorted(got['quotas'][0]),
          sorted(['addresses', 'cycle', 'description', 'down', 'enabled', 'end', 'host', 'kind', 'minutes',
                  'minutes_limit', 'over', 'over_at', 'percent', 'reset_at', 'start', 'state',
                  'up', 'used', 'uuid', 'volume', 'why']))

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
