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
    addresses - link-local and the firewall's left out; the alias missing, not the plugin's or switched
    off: no table written;
  - the cut, by the read that blocks, with os-xgs-npu or without it - a boot, the plugin off and on, a
    CARP master's return, a Reset and a second overrun, quota_over not yet in XGS: Settings' cut list - and
    a stand-in of os-xgs-npu's lists_cut.py finding nothing left after it; nothing cut where the owner took
    quota_over out of that list;
  - the cut in hardware first, through a stand-in of os-xgs-npu's hwdrop.py: called once, before the first
    pf state is killed, with the host's addresses alone; its count in the answer and the system log; the
    pf cut going on without it - hwdrop.py missing or not loading, raising, past its deadline or stuck in
    the driver - and nothing asked of it without os-xgs-npu; within() itself;
  - the hand-back: an address the table loses - a Reset, a new cycle, its quota removed or given another
    host, a MAC's address changed, the plugin off at the minute's read and at --flush - handed back from
    hardware, one it keeps not; its count in the answer and the log; hwdrop missing, older than
    release_addresses, raising or late: the read goes on, and what was not handed back is tried at the
    next read unless the table holds it again; nothing without os-xgs-npu;
  - off, a CARP backup, the interfaces unreadable: nothing counted, and off the table emptied;
  - a reset by hand; the command line - one read, --flush, --gone, --reset - its lock, its answer when a
    read stops; and the page's status.

    python3 tools/test-account.py"""
import calendar
import contextlib
import io
import ipaddress
import json
import os
import signal
import sys
import tempfile
import threading
import time
import types

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


def forget(text, ident):
    """pf's states' text without the state of this id/creatorid: what is left once it is killed."""
    mark = 'id: %s creatorid: %s' % tuple(ident.split('/'))
    blocks = []
    for line in text.splitlines():
        if line and not line[0].isspace():
            blocks.append([line])
        elif blocks:
            blocks[-1].append(line)
    kept = [block for block in blocks if not any(mark in rest for rest in block[1:])]
    return ''.join(line + '\n' for block in kept for line in block)


class FakePf(enforce.Pf):
    """pfctl: its states' text, the table quota_over (None: no such table), the states killed - also in
    events, when given, beside what else happens there. vanish: a state killed leaves the text, as pf
    forgets it."""

    def __init__(self, text='', table=None, fail=(), events=None, vanish=False):
        self.text = text
        self.table = set(table) if table is not None else None
        self.killed = []
        self.calls = []
        self.fail = set(fail)
        self.events = events
        self.vanish = vanish
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
            if self.events is not None:
                self.events.append(('kill', args[3]))
            if self.vanish:
                self.text = forget(self.text, args[3])
            return 0, ''
        if args == ['-v', '-s', 'Tables']:
            return 0, ('-pa----\tquota_over\n' if self.table is not None else '') + '-pa-r--\tbogons\n'
        return 1, 'pfctl: not this'


ABSENT = os.path.join(ROOT, 'tools', 'no-such-folder', 'hwdrop.py')     # an os-xgs-npu with no hwdrop.py


class FakeFw:
    def __init__(self, own=('192.0.2.1', '203.0.113.2', '2001:db8:1::1'), role=None, error=None, table=None,
                 project=False, hwdrop=ABSENT):
        self.own, self.role, self.error, self.table, self.project = set(own), role, error, table or {}, project
        self.hwdrop = hwdrop
        self.asked = 0

    def interfaces(self):
        return set(self.own), self.role, self.error

    def neighbours(self):
        self.asked += 1
        return {k: list(v) for k, v in self.table.items()}, 'hostwatch', None


def quota(uuid, host, volume=None, minutes=None, cycle='day', enabled=True, description=''):
    return {'uuid': uuid, 'enabled': enabled, 'host_text': host, 'host': settings.host(host),
            'volume': volume, 'minutes': minutes, 'cycle': cycle, 'description': description}


def conf(*quotas, enabled=True, minute_kb=100, cut_lists=(), cut_added=()):
    return {'read': True, 'enabled': enabled, 'minute_bytes': minute_kb * 1000, 'quotas': list(quotas),
            'xgs': bool(cut_lists or cut_added), 'cut_lists': list(cut_lists), 'count_to_pf': None,
            'cut_in_hardware': None, 'cut_added': list(cut_added)}


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
    with open(config, 'w', encoding='utf-8') as handle:
        handle.write('<opnsense><OPNsense><Quota><general><enabled>1</enabled><minute_threshold/></general></Quota>'
                     '</OPNsense></opnsense>')
    check('the minute threshold left empty, as Settings saves it unless the owner types one: the plugin\'s own value',
          (settings.read(config)['minute_bytes'], settings.MINUTE_KB * 1000), (100000, 100000))

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
# with os-xgs-npu, quota_over in its cut list: cut here all the same, by the read that blocks
LISTED = {'cut_lists': ['o1', OURS['uuid']], 'cut_added': [OURS['uuid']]}
records = tempfile.TemporaryDirectory()
RECORD = os.path.join(records.name, 'quota_over.json')         # os-xgs-npu's lists_cut.py's, below
state2 = json.loads(json.dumps(state))
pf2 = FakePf(pf.text, table=set())
answer = account.tick(state2, conf(qv, **LISTED), OURS, pf2, FakeFw(project=True), t0 + 240)
check('with os-xgs-npu and quota_over in XGS: Settings\' cut list: in the table, and its connections cut here, by the '
      'read that blocks it - not left to that list\'s next minute', (pf2.table, sorted(pf2.killed), answer.get('cut')),
      ({'192.0.2.10'}, ['0001/44128282', '0002/44128282', '0101/44128282'], 3))
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

# a clock that ran a day ahead at 10:00, a read in that day, and the clock put right at 10:05
state = {}
nine = utc(2026, 11, 20, 9, 0, 5)
pf = FakePf(pair(50123, 0, 0, 1, ['0001', '0002']), table=set())
account.tick(state, conf(qv), OURS, pf, fw, nine)
pf.text = pair(50123, 1200000, 0, 61, ['0001', '0002'])
account.tick(state, conf(qv), OURS, pf, fw, nine + 60)
before_jump = (q_state(state, U1)['over'], sorted(pf.table))
pf.text = pair(50123, 1300000, 0, 121, ['0001', '0002'])
account.tick(state, conf(qv), OURS, pf, fw, utc(2026, 11, 21, 10, 0, 5))
in_the_future = (q_state(state, U1)['start'], q_state(state, U1)['up'], sorted(pf.table))
LOGGED.clear()
pf.text = pair(50123, 1350000, 0, 181, ['0001', '0002'])
account.tick(state, conf(qv), OURS, pf, fw, utc(2026, 11, 20, 10, 5, 5))
check('a clock a day ahead and back: the turn it made early undone - today\'s cycle again, its 1.2 MB with the '
      '0.1 MB counted meanwhile and what came since, the host blocked again, said once',
      (before_jump, in_the_future, q_state(state, U1)['start'], q_state(state, U1)['up'], q_state(state, U1)['over'],
       sorted(pf.table), len([m for m in LOGGED if 'back in the cycle' in m])),
      ((True, ['192.0.2.10']), (utc(2026, 11, 21), 100000, []), utc(2026, 11, 20), 1350000, True, ['192.0.2.10'], 1))
pf.text = pair(50123, 1350000, 0, 241, ['0001', '0002'])
account.tick(state, conf(qv), OURS, pf, fw, utc(2026, 11, 21, 0, 0, 30))
check('... and the real midnight starts the next cycle: the host passes', (q_state(state, U1)['start'],
                                                                         q_state(state, U1)['up'], pf.table),
      (utc(2026, 11, 21), 0, set()))
# a real-time clock that lost its time, before NTP sets it: nothing goes back, nothing is given
state = {}
pf = FakePf(pair(50123, 0, 0, 1, ['0001', '0002']), table=set())
account.tick(state, conf(qv), OURS, pf, fw, utc(2026, 11, 19, 23, 59, 5))
pf.text = pair(50123, 300000, 0, 61, ['0001', '0002'])
account.tick(state, conf(qv), OURS, pf, fw, utc(2026, 11, 20, 0, 0, 5))
pf.text = pair(50123, 1200000, 0, 121, ['0001', '0002'])
account.tick(state, conf(qv), OURS, pf, fw, utc(2026, 11, 20, 0, 1, 5))
pf.text = pair(50123, 1200000, 0, 181, ['0001', '0002'])
account.tick(state, conf(qv), OURS, pf, fw, utc(2001, 1, 1, 0, 0, 5))
lost = (q_state(state, U1)['start'], q_state(state, U1)['up'], sorted(pf.table))
pf.text = pair(50123, 1250000, 0, 241, ['0001', '0002'])
account.tick(state, conf(qv), OURS, pf, fw, utc(2026, 11, 20, 0, 3, 5))
check('a real-time clock at 2001 after a boot, then set by NTP: today\'s cycle kept through it, the host blocked '
      'through it, and counted on', (lost, q_state(state, U1)['start'], q_state(state, U1)['up']),
      ((utc(2026, 11, 20), 1200000, ['192.0.2.10']), utc(2026, 11, 20), 1250000))
# a reset while the clock is ahead is not undone when it comes back
state = {}
pf = FakePf(pair(50123, 0, 0, 1, ['0001', '0002']), table=set())
account.tick(state, conf(qv), OURS, pf, fw, nine)
pf.text = pair(50123, 1200000, 0, 61, ['0001', '0002'])
account.tick(state, conf(qv), OURS, pf, fw, nine + 60)
account.tick(state, conf(qv), OURS, pf, fw, utc(2026, 11, 21, 10, 0, 5))
account.reset(state, U1, conf(qv))
account.tick(state, conf(qv), OURS, pf, fw, utc(2026, 11, 20, 10, 5, 5))
check('a reset by hand while the clock was ahead: not undone when it comes back', (q_state(state, U1)['up'], pf.table),
      (0, set()))

# --- the cut with os-xgs-npu: here, at once, in every case; a stand-in of its lists_cut.py, which keeps its
# record of the table on disk, finds nothing left after it


def lists_cut(pf):
    """os-xgs-npu's lists_cut.py for the table quota_over, as its run compares: what the table holds that
    its record of the last run does not is new, and every state with an end in it is killed; then the
    record is what the table holds now. No record: everything is new (its first run)."""
    now = set(pf.table or ())
    try:
        with open(RECORD, encoding='utf-8') as handle:
            before = set(json.load(handle))
    except (OSError, ValueError):
        before = None
    new = {a for a in now if before is None or str(ipaddress.ip_network(a)) not in before}
    killed = enforce.cut(pf, sorted(new))
    with open(RECORD, 'w', encoding='utf-8') as handle:
        json.dump(sorted(str(ipaddress.ip_network(a)) for a in now), handle)
    return killed


def gone_over(settings_=LISTED, firewall=None):
    """A host gone over its volume quota at t0 + 60, os-xgs-npu's lists_cut.py run once before; pf forgets
    a state once it is killed."""
    if os.path.exists(RECORD):
        os.remove(RECORD)
    state = {}
    pf = FakePf(pair(50123, 0, 0, 1, ['0001', '0002']), table=set(), vanish=True)
    firewall = firewall or FakeFw(project=True)
    account.tick(state, conf(qv, **settings_), OURS, pf, firewall, t0)
    lists_cut(pf)
    pf.text = pair(50123, 2 * MB, 0, 61, ['0001', '0002']) + inbound(40000, 5, 5, 61, '0101', host='192.0.2.10')
    account.tick(state, conf(qv, **settings_), OURS, pf, firewall, t0 + 60)
    return state, pf


ALL = ['0001/44128282', '0002/44128282', '0101/44128282']
LATER = ['0201/44128282', '0202/44128282']                 # what the host opened since
state, pf = gone_over()
check('with os-xgs-npu: a host gone over, new to lists_cut.py - every connection of it cut here, by the read that '
      'blocks it, and lists_cut.py\'s next run finds nothing left', (sorted(pf.killed), lists_cut(pf)), (ALL, 0))
# a reboot: pf's table empty, the record of lists_cut.py's last run still holding the host
pf.table, pf.killed = set(), []
pf.text = pair(50300, 0, 0, 5, ['0201', '0202'])
answer = account.tick(state, conf(qv, **LISTED), OURS, pf, FakeFw(project=True), t0 + 120)
check('a boot: the table filled again, and the host\'s connections cut here - lists_cut.py, its record from before '
      'the boot holding the host, would never take it as new', (pf.table, answer['added'], sorted(pf.killed),
                                                              lists_cut(pf)), ({'192.0.2.10'}, 1, LATER, 0))
# turned off and on: off empties the table and takes quota_over out of the cut list
state, pf = gone_over()
lists_cut(pf)
account.tick(state, conf(qv, enabled=False, **LISTED), OURS, pf, FakeFw(project=True), t0 + 120)
pf.text, pf.killed = pair(50300, 0, 0, 5, ['0201', '0202']), []
account.tick(state, conf(qv, **LISTED), OURS, pf, FakeFw(project=True), t0 + 180)
check('turned off, then on again: the host back in the table and its connections cut here',
      (pf.table, sorted(pf.killed), lists_cut(pf)), ({'192.0.2.10'}, LATER, 0))
# CARP: master, backup a while, master again - the host in the table all along
state, pf = gone_over()
lists_cut(pf)
account.tick(state, conf(qv, **LISTED), OURS, pf, FakeFw(project=True, role='backup'), t0 + 120)
pf.text, pf.killed = pair(50300, 0, 0, 5, ['0201', '0202']), []         # pfsync's copies from the other one
answer = account.tick(state, conf(qv, **LISTED), OURS, pf, FakeFw(project=True), t0 + 180)
check('a CARP master again, the host in its table all along: what pfsync brought of it cut here',
      (answer['added'], sorted(pf.killed), lists_cut(pf)), (0, LATER, 0))
state, pf = gone_over(firewall=FakeFw())
account.tick(state, conf(qv), OURS, pf, FakeFw(role='backup'), t0 + 120)
pf.text, pf.killed = pair(50300, 0, 0, 5, ['0201', '0202']), []
account.tick(state, conf(qv), OURS, pf, FakeFw(), t0 + 180)
check('... and without os-xgs-npu the same', sorted(pf.killed), LATER)
pf.killed = []
account.tick(state, conf(qv), OURS, pf, FakeFw(), t0 + 240)
check('... once: the next read cuts nothing again', pf.killed, [])
# a reset, and over again before lists_cut.py's next run: its record still holds the host
state, pf = gone_over()
lists_cut(pf)
account.reset(state, U1, conf(qv, **LISTED))
pf.text = pair(50300, 0, 0, 5, ['0201', '0202'])                         # a connection made again
account.tick(state, conf(qv, **LISTED), OURS, pf, FakeFw(project=True), t0 + 70)
passed = set(pf.table)
pf.text, pf.killed = pair(50300, 2 * MB, 0, 15, ['0201', '0202']), []
account.tick(state, conf(qv, **LISTED), OURS, pf, FakeFw(project=True), t0 + 80)
check('reset, then over again within lists_cut.py\'s minute: out of the table, back in it, and cut here',
      (passed, pf.table, sorted(pf.killed), lists_cut(pf)), (set(), {'192.0.2.10'}, LATER, 0))
# quota_over never put in the cut list - os-xgs-npu installed since the last Apply
state, pf = gone_over(settings_={'cut_lists': ['o1']})
check('quota_over not yet in XGS: Settings\' cut list (os-xgs-npu installed since the last Apply): cut here, at once',
      sorted(pf.killed), ALL)
# taken out of it by the owner
state, pf = gone_over(settings_={'cut_lists': ['o1'], 'cut_added': [OURS['uuid']]})
check('quota_over taken out of the cut list by the owner: nothing cut - his choice', pf.killed, [])
# until 2026-11-20 the read looked for lists_cut.py's record (/var/db/os-xgs-npu/lists/quota_over.json, here
# absent, so the cases above cut here then too) and left an address it did not hold to that list's next minute
check('lists_cut.py\'s record of the table no longer read: the read cuts whether that list would take the address as '
      'new or not', (hasattr(account, 'LISTS_RECORD'), account.cut_here({'192.0.2.10'}, conf(qv, **LISTED), OURS, True)),
      (False, {'192.0.2.10'}))
records.cleanup()

# --- the cut in hardware first: a stand-in of os-xgs-npu's hwdrop.py, in a folder of its own beside a flows.py,
# as os-blocklists' tools/test-hwdrop.py has it. result: a count, None (raises), 'slow' (pages through a flow
# table of EVENTS.conns connections, EVENTS.each seconds each, as hwdrop does: a generator that holds the
# flow-table lock and puts the shared page place back in its finally, an `in` test for every connection, a
# verdict for each that matches) or 'stuck' (one driver call of 3 s that never looks back)
FAKE_HWDROP = '''
import os
import sys
import threading
import time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import flows  # noqa: E402,F401 - os-xgs-npu's hwdrop imports its flows.py this way
import hwdrop_events  # noqa: E402


def pages():
    hwdrop_events.lock.append(threading.current_thread().name)
    try:
        for i in range(hwdrop_events.conns):
            time.sleep(hwdrop_events.each)
            yield i
    finally:
        hwdrop_events.events.append(('place 0', threading.current_thread().name, time.monotonic()))
        hwdrop_events.lock.clear()


def walk(contains):
    dropped = 0
    for i in pages():
        if hwdrop_events.probe[0] in contains:
            hwdrop_events.events.append(('verdict', i, time.monotonic()))
            dropped += 1
    return dropped


def answer(contains):
    if hwdrop_events.result == 'slow':
        return walk(contains)
    if hwdrop_events.result == 'stuck':
        time.sleep(3)
        return 9
    if hwdrop_events.result is None:
        raise RuntimeError('no table')
    return hwdrop_events.result


def drop_addresses(contains, path='/conf/config.xml'):
    hwdrop_events.events.append(('drop_addresses', sorted(a for a in hwdrop_events.probe if a in contains)))
    return answer(contains)


def release_addresses(contains):
    hwdrop_events.events.append(('release_addresses', sorted(a for a in hwdrop_events.probe if a in contains)))
    return answer(contains)
'''
EVENTS = types.ModuleType('hwdrop_events')
EVENTS.events, EVENTS.probe, EVENTS.result, EVENTS.lock, EVENTS.conns, EVENTS.each = [], [], 0, [], 20, 0.3
sys.modules['hwdrop_events'] = EVENTS
hardware = tempfile.TemporaryDirectory()
HWDROP = os.path.join(hardware.name, 'xgs', 'hwdrop.py')
os.makedirs(os.path.dirname(HWDROP))
with open(HWDROP, 'w', encoding='utf-8') as handle:
    handle.write(FAKE_HWDROP)
with open(os.path.join(hardware.name, 'xgs', 'flows.py'), 'w', encoding='utf-8') as handle:
    handle.write('')
NO_HWDROP = os.path.join(hardware.name, 'absent', 'hwdrop.py')
# an os-xgs-npu older than hwdrop's release_addresses (2026-11-17): it drops, and hands nothing back by address
OLDER = os.path.join(hardware.name, 'older', 'hwdrop.py')
os.makedirs(os.path.dirname(OLDER))
with open(OLDER, 'w', encoding='utf-8') as handle:
    handle.write(FAKE_HWDROP[:FAKE_HWDROP.index('def release_addresses')])
with open(os.path.join(os.path.dirname(OLDER), 'flows.py'), 'w', encoding='utf-8') as handle:
    handle.write('')


def kinds(events):
    return [e[0] for e in events if e[0] in ('drop_addresses', 'release_addresses', 'kill')]


def settle(wait=6):
    """Every hardware step left at its deadline, ended."""
    until = time.monotonic() + wait
    for t in list(enforce._left):
        t.join(max(0, until - time.monotonic()))
    enforce._left[:] = [t for t in enforce._left if t.is_alive()]
    return not enforce._left


def place_back(wait=3):
    """The stand-in's page place put back (its paging generator's finally): (thread, when), or None."""
    until = time.monotonic() + wait
    while time.monotonic() < until:
        for e in list(EVENTS.events):
            if e[0] == 'place 0':
                return e[1], e[2]
        time.sleep(0.05)
    return None


def hw_over(result, path=HWDROP, settings_=LISTED, project=True, quota_=None, table=None):
    """A host gone over its volume quota at t0 + 60, os-xgs-npu's hwdrop.py at path answering result:
    (the read's answer, what happened in order - the drop and pf's kills - what the log was told, the
    read's seconds, whether the module search path is as it was)."""
    EVENTS.events[:], EVENTS.result, EVENTS.lock[:] = [], result, []
    EVENTS.probe = ['192.0.2.10', '2001:db8:1::10', '192.0.2.11', '198.51.100.7']
    state = {}
    pf = FakePf(pair(50123, 0, 0, 1, ['0001', '0002']), table=set(), events=EVENTS.events)
    firewall = FakeFw(project=project, hwdrop=path, table=table)
    account.tick(state, conf(quota_ or qv, **settings_), OURS, pf, firewall, t0)
    pf.text = pair(50123, 2 * MB, 0, 61, ['0001', '0002']) + inbound(40000, 5, 5, 61, '0101', host='192.0.2.10')
    LOGGED.clear()
    before = list(sys.path)
    started = time.monotonic()
    answer = account.tick(state, conf(quota_ or qv, **settings_), OURS, pf, firewall, t0 + 60)
    took = time.monotonic() - started
    return answer, list(EVENTS.events), list(LOGGED), took, sys.path == before


def cut_lines(logged):
    return [m for m in logged if 'over their quota cut' in m]


CUT3 = '3 open connection(s) of 1 host address(es) over their quota cut'
answer, events, logged, took, kept = hw_over(3)
check('with os-xgs-npu: a host gone over has its connections dropped on the coprocessor once, before the first pf '
      'state is killed - then every state of it killed', kinds(events), ['drop_addresses', 'kill', 'kill', 'kill'])
check('... the drop asked for the host\'s address alone', events[0], ('drop_addresses', ['192.0.2.10']))
check('... how many it dropped in the answer, beside the kills', (answer.get('dropped'), answer.get('cut')), (3, 3))
check('... and in the system log\'s line', cut_lines(logged), [CUT3 + ', 3 dropped in hardware first'])
check('... the module search path as it was', kept, True)
answer, events, logged, took, kept = hw_over(4, quota_=quota(U1, '02:00:00:aa:bb:cc', volume=MB),
                                             table={'02:00:00:aa:bb:cc': ['192.0.2.10', '2001:db8:1::10']})
check('a MAC over its quota: both its addresses in the one drop', (events[0], answer.get('dropped'), cut_lines(logged)),
      (('drop_addresses', ['192.0.2.10', '2001:db8:1::10']), 4,
       ['3 open connection(s) of 2 host address(es) over their quota cut, 4 dropped in hardware first']))
answer, events, logged, took, kept = hw_over(0)
check('"Cut in hardware" off - hwdrop drops none: 0 in the answer and the log, every state killed as before',
      (answer.get('dropped'), answer.get('cut'), cut_lines(logged)), (0, 3, [CUT3 + ', 0 dropped in hardware first']))
answer, events, logged, took, kept = hw_over(3, settings_={'cut_lists': ['o1'], 'cut_added': [OURS['uuid']]})
check('quota_over taken out of the cut list by the owner: nothing dropped in hardware, nothing killed, nothing said',
      (events, 'cut' in answer, 'dropped' in answer, cut_lines(logged)), ([], False, False, []))
answer, events, logged, took, kept = hw_over(3, settings_={'cut_lists': ['o1']})
check('quota_over not yet in the cut list: dropped in hardware first all the same',
      (kinds(events), answer.get('dropped')), (['drop_addresses', 'kill', 'kill', 'kill'], 3))
answer, events, logged, took, kept = hw_over(3, project=False, settings_={})
check('without os-xgs-npu: nothing asked of a hwdrop.py, pf alone, the log\'s line as before',
      (kinds(events), 'dropped' in answer, cut_lines(logged)), (['kill', 'kill', 'kill'], False, [CUT3]))
answer, events, logged, took, kept = hw_over(3, path=NO_HWDROP)
check('os-xgs-npu with no hwdrop.py: pf alone - every state killed, no "dropped", the log\'s line as before',
      (kinds(events), 'dropped' in answer, cut_lines(logged)), (['kill', 'kill', 'kill'], False, [CUT3]))
broken = os.path.join(hardware.name, 'broken', 'hwdrop.py')
os.makedirs(os.path.dirname(broken))
with open(broken, 'w', encoding='utf-8') as handle:
    handle.write('import no_such_module_here\n')
answer, events, logged, took, kept = hw_over(3, path=broken)
check('a hwdrop.py that does not load: as with none, said, the module search path as it was',
      (kinds(events), 'dropped' in answer, any('could not be loaded' in m for m in logged), kept),
      (['kill', 'kill', 'kill'], False, True, True))
answer, events, logged, took, kept = hw_over(None)
check('a hwdrop that raises: the pf cut goes on - every state killed - and how many it dropped is not known',
      (kinds(events), answer.get('dropped'), answer.get('cut')), (['drop_addresses', 'kill', 'kill', 'kill'], 'unknown', 3))
check('... said: what it raised, and the cut\'s line', (any('failed' in m and 'no table' in m for m in logged),
                                                     cut_lines(logged)),
      (True, [CUT3 + ', how many were dropped in hardware first is not known']))
# past its deadline (1 s here): left there, the pf cut at once; stopped at its next connection, no verdict
# after the deadline, the page place put back in its own thread
saved = enforce.HW_DEADLINE
enforce.HW_DEADLINE = 1
try:
    answer, events, logged, took, kept = hw_over('slow')
finally:
    enforce.HW_DEADLINE = saved
returned = time.monotonic()
check('a hardware step paging slowly past its deadline: left at 1 s, the states killed - the read done in %.2f s' % took,
      (kinds(events), answer.get('dropped'), answer.get('cut'), took < 1.6),
      (['drop_addresses', 'kill', 'kill', 'kill'], 'unknown', 3, True))
check('... said in the system log', any('took more than 1 s' in m and 'not known' in m for m in logged), True)
back = place_back()
check('... the step stopped at its next connection, the page place put back and the lock let go in its own thread',
      (back is not None and back[0] == 'quota-hwdrop' and back[1] - returned < 0.6, EVENTS.lock), (True, []))
verdicts = [e for e in EVENTS.events if e[0] == 'verdict']
check('... no verdict written after the deadline (%d before it)' % len(verdicts),
      bool(verdicts) and all(e[2] <= returned + 0.05 for e in verdicts), True)
check('... and it has ended', settle(), True)
# stuck in one call that never looks back: nothing held up, and no second step beside it
enforce.HW_DEADLINE = 1
try:
    answer, events, logged, took, kept = hw_over('stuck')
    check('a hardware step stuck in the driver: left at 1 s, the states killed - the read done in %.2f s' % took,
          (kinds(events), answer.get('dropped'), took < 1.6), (['drop_addresses', 'kill', 'kill', 'kill'], 'unknown', True))
    answer, events, logged, took, kept = hw_over(3)
    check('... while it runs, no second step beside it: the states killed, how many dropped not known, said',
          (kinds(events), answer.get('dropped'), any('still runs' in m for m in logged)),
          (['kill', 'kill', 'kill'], 'unknown', True))
finally:
    enforce.HW_DEADLINE = saved
check('... it ends', settle(), True)
answer, events, logged, took, kept = hw_over(3)
check('... and then the hardware step runs again', answer.get('dropped'), 3)
# the hand-back: what the coprocessor dropped for an address the table loses, handed back to the host
QB = quota(U2, '192.0.2.11', volume=MB, description='Lab')


def blocked(quotas=None, path=HWDROP, project=True, table=None):
    """Hosts gone over their volume quotas at t0 + 60 - their connections dropped in hardware and cut -
    with os-xgs-npu's hwdrop.py at path: (state, pf, firewall) for the reads after. pf forgets a state it
    kills."""
    EVENTS.events[:], EVENTS.result, EVENTS.lock[:] = [], 3, []
    EVENTS.probe = ['192.0.2.10', '192.0.2.11', '2001:db8:1::10', '2001:db8:1::77', '198.51.100.7']
    state = {}
    quotas = quotas or [qv]
    pf = FakePf(pair(50123, 0, 0, 1, ['0001', '0002']) + pair(50124, 0, 0, 1, ['0003', '0004'], host='192.0.2.11'),
                table=set(), events=EVENTS.events, vanish=True)
    firewall = FakeFw(project=project, hwdrop=path, table=table)
    account.tick(state, conf(*quotas, **LISTED), OURS, pf, firewall, t0)
    pf.text = (pair(50123, 2 * MB, 0, 61, ['0001', '0002']) +
               pair(50124, 2 * MB, 0, 61, ['0003', '0004'], host='192.0.2.11'))
    account.tick(state, conf(*quotas, **LISTED), OURS, pf, firewall, t0 + 60)
    return state, pf, firewall


def later(state, pf, firewall, result, when, quotas=None, enabled=True):
    """One read after, hwdrop answering result: (its answer, what happened in order, what the log was told,
    the read's seconds)."""
    EVENTS.events[:], EVENTS.result, EVENTS.lock[:] = [], result, []
    LOGGED.clear()
    started = time.monotonic()
    answer = account.tick(state, conf(*(quotas or [qv]), enabled=enabled, **LISTED), OURS, pf, firewall, when)
    return answer, list(EVENTS.events), list(LOGGED), time.monotonic() - started


def back_lines(logged):
    return [m for m in logged if 'handed back from hardware' in m]


state, pf, firewall = blocked()
dropped_first = (pf.table, sorted(pf.killed))
account.reset(state, U1, conf(qv, **LISTED))
answer, events, logged, took = later(state, pf, firewall, 2, t0 + 70)
check('a Reset: the host out of the table, and what the coprocessor dropped for it handed back - its address alone, '
      'once', (dropped_first, pf.table, kinds(events), events[:1]),
      (({'192.0.2.10'}, ['0001/44128282', '0002/44128282']), set(), ['release_addresses'],
       [('release_addresses', ['192.0.2.10'])]))
check('... how many in the answer and the system log, nothing kept', (answer.get('released'), back_lines(logged),
                                                                     'release' in state),
      (2, ['2 connection(s) of 1 host address(es) no longer over their quota handed back from hardware'], False))
answer, events, logged, took = later(state, pf, firewall, 2, t0 + 130)
check('... and the next read hands back nothing again', (events, 'released' in answer), ([], False))
# two hosts over, one reset: the other stays blocked, and dropped
state, pf, firewall = blocked(quotas=[qv, QB])
account.reset(state, U1, conf(qv, QB, **LISTED))
answer, events, logged, took = later(state, pf, firewall, 2, t0 + 70, quotas=[qv, QB])
check('two hosts over, one reset: its address handed back, the other\'s not - still in the table',
      (events, pf.table), ([('release_addresses', ['192.0.2.10'])], {'192.0.2.11'}))
# a quota removed
state, pf, firewall = blocked(quotas=[qv, QB])
answer, events, logged, took = later(state, pf, firewall, 1, t0 + 120, quotas=[QB])
check('a quota removed: its host\'s address handed back, the other host\'s kept blocked',
      (events, answer.get('released'), pf.table), ([('release_addresses', ['192.0.2.10'])], 1, {'192.0.2.11'}))
state, pf, firewall = blocked()
answer, events, logged, took = later(state, pf, firewall, 1, t0 + 120, quotas=[quota(U1, '192.0.2.12', volume=MB)])
check('a quota given another host: the old one\'s address handed back, the new one not blocked',
      (events, answer.get('released'), pf.table), ([('release_addresses', ['192.0.2.10'])], 1, set()))
# a cycle that starts again
state, pf, firewall = blocked()
answer, events, logged, took = later(state, pf, firewall, 2, utc(2026, 11, 21, 0, 0, 30))
check('a new cycle: the host passes again, and what was dropped for it is handed back',
      (pf.table, events, answer.get('released')), (set(), [('release_addresses', ['192.0.2.10'])], 2))
# the plugin turned off: the minute's read, and Apply's --flush
state, pf, firewall = blocked()
answer, events, logged, took = later(state, pf, firewall, 2, t0 + 120, enabled=False)
check('the plugin off, the minute\'s read: the table emptied, its address handed back',
      (answer['status'], pf.table, events, answer.get('released')),
      ('off', set(), [('release_addresses', ['192.0.2.10'])], 2))
calls = len(pf.calls)
answer, events, logged, took = later(state, pf, firewall, 2, t0 + 180, enabled=False)
check('... the next read while off: nothing asked of pf or hwdrop', (len(pf.calls) - calls, events, 'released' in answer),
      (0, [], False))
state, pf, firewall = blocked()
flushed = os.path.join(hardware.name, 'flush')
os.makedirs(flushed)
with open(os.path.join(flushed, 'config.xml'), 'w', encoding='utf-8') as handle:
    handle.write('<opnsense><OPNsense><Quota><general><enabled>0</enabled></general></Quota><Firewall><Alias><aliases>'
                 '<alias uuid="%s"><enabled>1</enabled><name>quota_over</name><type>external</type><description>Quotas: '
                 'hosts over their quota</description></alias></aliases></Alias></Firewall></OPNsense></opnsense>'
                 % OURS['uuid'])
account.save(state, os.path.join(flushed, 'state.json'))
EVENTS.events[:], EVENTS.result = [], 2
said = io.StringIO()
with contextlib.redirect_stdout(said):
    account.main(['account.py', '--flush'], pf=pf, fw=firewall, config=os.path.join(flushed, 'config.xml'),
                 path=os.path.join(flushed, 'state.json'), lock=os.path.join(flushed, 'account.lock'))
out = json.loads(said.getvalue())
check('account.py --flush (Apply turning it off, the removal): the table emptied, what it held handed back',
      (out['emptied'], pf.table, EVENTS.events[:], out.get('released')),
      (1, set(), [('release_addresses', ['192.0.2.10'])], 2))
# without os-xgs-npu, with no hwdrop.py, with one older than release_addresses: nothing handed back, nothing kept
for what, kwargs in (('without os-xgs-npu', {'project': False}), ('with no hwdrop.py', {'path': NO_HWDROP}),
                     ('with a hwdrop.py older than release_addresses', {'path': OLDER})):
    state, pf, firewall = blocked(**kwargs)
    account.reset(state, U1, conf(qv, **LISTED))
    answer, events, logged, took = later(state, pf, firewall, 2, t0 + 70)
    check('%s: the host out of the table, nothing handed back, nothing kept, nothing said' % what,
          (pf.table, kinds(events), 'released' in answer, 'release' in state, back_lines(logged), answer['status']),
          (set(), [], False, False, [], 'ok'))
# hwdrop raising: the read goes on; the address kept and handed back at the next read
state, pf, firewall = blocked()
account.reset(state, U1, conf(qv, **LISTED))
answer, events, logged, took = later(state, pf, firewall, None, t0 + 70)
check('the hand-back raising: the read goes on - the host out of the table, the answer ok - how many not known, '
      'its address kept, said', (answer['status'], pf.table, answer.get('released'), state.get('release'),
                                 any('failed' in m and 'tried again at the next read' in m for m in logged)),
      ('ok', set(), 'unknown', ['192.0.2.10'], True))
answer, events, logged, took = later(state, pf, firewall, 2, t0 + 130)
check('... the next read hands it back, and keeps nothing', (events, answer.get('released'), 'release' in state),
      ([('release_addresses', ['192.0.2.10'])], 2, False))
# past its deadline: the read goes on at once, the address kept
state, pf, firewall = blocked()
account.reset(state, U1, conf(qv, **LISTED))
enforce.HW_DEADLINE = 1
try:
    answer, events, logged, took = later(state, pf, firewall, 'slow', t0 + 70)
finally:
    enforce.HW_DEADLINE = saved
check('the hand-back past its deadline (1 s here): left there, the read done in %.2f s, how many not known, the '
      'address kept, said' % took, (took < 1.6, answer['status'], pf.table, answer.get('released'),
                                    state.get('release'), any('took more than 1 s' in m for m in logged)),
      (True, 'ok', set(), 'unknown', ['192.0.2.10'], True))
check('... it ends', settle(), True)
# kept, and over its quota again at the next read: blocked and dropped again, not handed back
pf.text = pair(50300, 2 * MB, 0, 5, ['0201', '0202'])
answer, events, logged, took = later(state, pf, firewall, 3, t0 + 80)
check('an address kept for the hand-back, back in the table before it: dropped and cut again, not handed back, '
      'no longer kept', (pf.table, kinds(events), 'released' in answer, 'release' in state),
      ({'192.0.2.10'}, ['drop_addresses', 'kill', 'kill'], False, False))
# a MAC's address changed while it is blocked: the new one dropped and cut, the old one handed back, in that order
state, pf, firewall = blocked(quotas=[quota(U1, '02:00:00:aa:bb:cc', volume=MB)],
                              table={'02:00:00:aa:bb:cc': ['192.0.2.10', '2001:db8:1::10']})
firewall.table['02:00:00:aa:bb:cc'] = ['192.0.2.10', '2001:db8:1::77']
answer, events, logged, took = later(state, pf, firewall, 1, t0 + 120, quotas=[quota(U1, '02:00:00:aa:bb:cc', volume=MB)])
check('a MAC\'s IPv6 address changed while it is blocked: the new one dropped first, the old one handed back after',
      (sorted(pf.table), events, answer.get('released')),
      (['192.0.2.10', '2001:db8:1::77'], [('drop_addresses', ['2001:db8:1::77']), ('release_addresses', ['2001:db8:1::10'])],
       1))
check('release_in_hardware with no hwdrop.py, and with one older than release_addresses: None',
      (enforce.release_in_hardware(['192.0.2.10'], NO_HWDROP), enforce.release_in_hardware(['192.0.2.10'], OLDER)),
      (None, None))
# the step itself
EVENTS.events[:], EVENTS.result = [], 2
check('drop_in_hardware: the addresses as hwdrop writes a connection\'s ends - IPv6 in its short form - and one '
      'that is not an address left out', (enforce.drop_in_hardware(['2001:DB8:1::0010', 'not an address'], HWDROP),
                                          EVENTS.events[:1]), (2, [('drop_addresses', ['2001:db8:1::10'])]))
check('drop_in_hardware with no hwdrop.py: None, nothing asked', (enforce.drop_in_hardware(['192.0.2.10'], NO_HWDROP),
                                                                  enforce.drop_in_hardware(['192.0.2.10'], None)),
      (None, None))
check('within(): the step\'s result', enforce.within(1, lambda stop, a: a + 1, 41), 42)
try:
    enforce.within(1, lambda stop: 1 / 0)
    raised = None
except RuntimeError as error:
    raised = str(error)
check('within(): what the step raised, as text', raised is not None and 'ZeroDivisionError' in raised, True)
started = time.monotonic()
try:
    enforce.within(0.5, lambda stop: time.sleep(2))
    late = False
except enforce.HardwareLate:
    late = True
took = time.monotonic() - started
check('within(): a step that never looks back is left at 0.5 s (%.2f s)' % took, (late, took < 0.8), (True, True))
try:
    enforce.within(0.5, lambda stop: 1)
    busy = False
except enforce.HardwareBusy:
    busy = True
check('within(): while it runs, no second step is started', busy, True)
check('within(): it ends, and then a step runs again', (settle(), enforce.within(0.5, lambda stop: 2)), (True, 2))
try:
    enforce.within(0.3, lambda stop: stop.wait(5))
except enforce.HardwareLate:
    pass
check('within(): a step waiting on its stop ends once it is set', settle(wait=0.5), True)
check('within() uses no signal and no timer: SIGALRM as it was, no real-time timer set',
      (signal.getsignal(signal.SIGALRM) == signal.SIG_DFL if hasattr(signal, 'SIGALRM') else True,
       signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0) if hasattr(signal, 'getitimer') else True), (True, True))
check('no hardware step left running', (settle(), [t.name for t in threading.enumerate() if t.name == 'quota-hwdrop']),
      (True, []))
hardware.cleanup()

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
# the owner's own alias named quota_over: his table never emptied - the plugin turned off after a host went
# over, or after the plugin's alias had held hosts and became his
state = {}
owner = dict(OURS, ours=False, type='host')
pf = FakePf(pair(50123, 0, 0, 1, ['0001', '0002']), table={'203.0.113.50', '203.0.113.51'})
account.tick(state, conf(qv), owner, pf, fw, t0)
pf.text = pair(50123, 2 * MB, 0, 61, ['0001', '0002'])
account.tick(state, conf(qv), owner, pf, fw, t0 + 60)
account.tick(state, conf(qv, enabled=False), owner, pf, fw, t0 + 120)
check('the owner\'s alias quota_over: a host over its quota, then the plugin off - his table as it was, nothing '
      'asked of it but to read it', (q_state(state, U1)['over'], pf.table,
                                    [c for c in pf.calls if ' -T ' in ' %s ' % c and not c.endswith('show')]),
      (True, {'203.0.113.50', '203.0.113.51'}, []))
state = {}
pf = FakePf(pair(50123, 0, 0, 1, ['0001', '0002']), table=set())
account.tick(state, conf(qv), OURS, pf, fw, t0)
pf.text = pair(50123, 2 * MB, 0, 61, ['0001', '0002'])
account.tick(state, conf(qv), OURS, pf, fw, t0 + 60)
pf.table |= {'203.0.113.50'}
account.tick(state, conf(qv, enabled=False), dict(OURS, ours=False), pf, fw, t0 + 120)
check('the plugin\'s alias made the owner\'s while hosts were in it, then the plugin off: the table left as it is',
      pf.table, {'192.0.2.10', '203.0.113.50'})
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

    def write_config(enabled='1', alias=True, owner=False):
        mine = ('<alias uuid="a1"><enabled>1</enabled><name>quota_over</name><type>external</type>'
                '<description>Quotas: hosts over their quota</description></alias>')
        his = ('<alias uuid="b1"><enabled>1</enabled><name>quota_over</name><type>host</type>'
               '<description>my own list</description></alias>')
        with open(config, 'w', encoding='utf-8') as handle:
            handle.write('<opnsense><OPNsense><Quota><general><enabled>%s</enabled></general><quotas><quota uuid="%s">'
                         '<enabled>1</enabled><host>192.0.2.10</host><volume>1</volume><cycle>day</cycle></quota></quotas>'
                         '</Quota><Firewall><Alias><aliases>%s</aliases></Alias></Firewall></OPNsense></opnsense>'
                         % (enabled, U1, his if owner else (mine if alias else '')))

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
    pf.table = {'192.0.2.10'}
    code, out = cli('--flush', pf=pf)
    check('account.py --flush: the plugin\'s table emptied, the counting paused',
          (out['status'], out['emptied'], pf.table, account.load(path)['conns']), ('ok', 1, set(), {}))
    write_config(owner=True)
    pf.table = {'203.0.113.50', '203.0.113.51'}
    code, out = cli('--flush', pf=pf)
    check('account.py --flush with the owner\'s alias quota_over (installing, upgrading or removing the plugin '
          'while it is off): his table left, said', (out['emptied'], pf.table, 'not this plugin' in out.get('note', '')),
          (None, {'203.0.113.50', '203.0.113.51'}, True))
    write_config(alias=False)
    code, out = cli('--flush', pf=pf)
    check('account.py --flush with no alias of that name: the table, left by the plugin, emptied',
          (out['emptied'], pf.table), (2, set()))
    write_config()
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
    pf.table = {'203.0.113.50'}
    code, out = cli('--flush', pf=pf)
    check('account.py --flush, config.xml unreadable - whose the table is cannot be told: left, said',
          (out['emptied'], pf.table, 'could not be read' in out.get('note', '')), (None, {'203.0.113.50'}, True))
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

    # the plugin removed while a read waits for the lock: uninstall.sh's rm -rf /var/db/os-quota
    import contextlib
    import io
    import shutil
    import threading
    gone_dir = os.path.join(tmp, 'os-quota')
    os.makedirs(gone_dir)
    gone_lock = os.path.join(gone_dir, 'account.lock')
    waited = {}

    def waiting():
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            account.main(['account.py'], pf=FakePf('', table=set()), fw=FakeFw(), config=config,
                         path=os.path.join(gone_dir, 'state.json'), lock=gone_lock)
        waited['answer'] = json.loads(out.getvalue())

    with open(gone_lock, 'a') as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        reader = threading.Thread(target=waiting)
        reader.start()
        time.sleep(0.6)
        shutil.rmtree(gone_dir)
    reader.join(10)
    check('a read that waited for the lock while the removal took /var/db/os-quota away: it ends, nothing written, '
          'the directory not made again', (waited.get('answer', {}).get('status'), os.path.exists(gone_dir)),
          ('removed', False))

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
          sorted(['alias', 'count_to_pf', 'counts', 'cut_in_hardware', 'cut_listed', 'cut_recorded', 'enabled', 'error',
                  'last', 'minute_bytes', 'near_percent', 'project', 'quotas', 'read', 'role', 'table', 'xgs']))
    check('status: quota_over in the cut list, not put there by the plugin (its record empty)',
          (got['cut_listed'], got['cut_recorded']), (True, False))
    check('status of a row: every key the grid reads', sorted(got['quotas'][0]),
          sorted(['addresses', 'cycle', 'description', 'down', 'enabled', 'end', 'host', 'kind', 'minutes',
                  'minutes_limit', 'over', 'over_at', 'percent', 'reset_at', 'start', 'state',
                  'up', 'used', 'uuid', 'volume', 'why']))

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
