#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""pf's states as the quotas read them (src/opnsense/scripts/quota/states.py), on the text `pfctl -vvs state`
gives on OPNsense 26.7 - tools/fixtures/states-26.7.txt, laid out as phase 0's A0 capture on the second
XGS 3300 and its masked sample, every address made a documentation one: a connection through outbound
NAT (its two states, the coprocessor's equal counts on both), a port forward, IPv6 both ways, UDP to the
firewall itself, ICMP, GRE (no ports), an if-bound state, a gateway or route-to on the id line, a redirect
to 127.0.0.1.

What is checked: each first line read for its protocol, its stack-side ends and which end made it; one
connection, one count - its states grouped by those ends, the largest count each way; bytes up from the one
that made it; ages; the ids; only the watched hosts' states read past their first line, with the same
answer whether the quick look-through is used or not; and what a cut kills - every state with an end, either
side of a translation, among the addresses given.

    python3 tools/test-states.py"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src', 'opnsense', 'scripts', 'quota'))
import states  # noqa: E402

failures = 0
checks = 0


def check(name, got, want):
    global failures, checks
    checks += 1
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


TEXT = open(os.path.join(ROOT, 'tools', 'fixtures', 'states-26.7.txt'), encoding='utf-8').read()

# the first lines
check('a "<-" line: the bare ends are the stack\'s, the second made it',
      states.header('all tcp 198.51.100.7:443 <- 192.0.2.10:50123       ESTABLISHED:ESTABLISHED')[:3],
      ('tcp', '192.0.2.10:50123', '198.51.100.7:443'))
check('a "->" line through NAT: the end in brackets is the stack\'s, the first made it',
      states.header('all tcp 203.0.113.2:61000 (192.0.2.10:50123) -> 198.51.100.7:443       ESTABLISHED:ESTABLISHED')[:3],
      ('tcp', '192.0.2.10:50123', '198.51.100.7:443'))
check('a "<-" line of a port forward: the bare ends - the inside server - and the sender made it',
      states.header('all tcp 192.0.2.11:80 (203.0.113.2:8080) <- 198.51.100.8:40000       ESTABLISHED:ESTABLISHED')[:3],
      ('tcp', '198.51.100.8:40000', '192.0.2.11:80'))
check('every address on a line, translated ones too',
      states.header('all tcp 203.0.113.2:61000 (192.0.2.10:50123) -> 198.51.100.7:443       ESTABLISHED:ESTABLISHED')[3],
      {'203.0.113.2', '192.0.2.10', '198.51.100.7'})
check('IPv6, address[port]', states.header('all tcp 2001:db8:1::10[50000] -> 2001:db8:ffff::7[443]       X:Y')[:3],
      ('tcp', '2001:db8:1::10[50000]', '2001:db8:ffff::7[443]'))
check('no ports (GRE)', states.header('all gre 192.0.2.10 -> 198.51.100.9       MULTIPLE:MULTIPLE')[:3],
      ('gre', '192.0.2.10', '198.51.100.9'))
check('an if-bound state', states.header('igb1 tcp 192.0.2.1:22 <- 192.0.2.12:40001       ESTABLISHED:ESTABLISHED')[:3],
      ('tcp', '192.0.2.12:40001', '192.0.2.1:22'))
for line in ('   age 00:01:00, expires in 00:00:30, 1:1 pkts, 1:1 bytes, rule 1', 'all tcp', '',
             'all tcp 192.0.2.10:1 = 198.51.100.7:2       X:Y', 'No ALTQ support in kernel'):
    check('not a first line: %r' % line[:40], states.header(line), None)
check('addresses as pf writes them', [states.address(e) for e in ('192.0.2.10:50123', '192.0.2.10', '2001:DB8::1[443]',
                                                                   '2001:db8::1', '(192.0.2.1:514)')],
      ['192.0.2.10', '192.0.2.10', '2001:db8::1', '2001:db8::1', '192.0.2.1'])

# one connection, one count
found, read = states.parse(TEXT, {'192.0.2.10'})
check('the states read: every first line', read, 13)
nat = found.get('tcp 192.0.2.10:50123 198.51.100.7:443')
check('the NAT\'d connection: one group of its two states, counted once', (len(found), nat and sorted(nat['ids'])),
      (4, ['2ef2fe6a00000000/44128282', '2ff2fe6a00000000/44128282']))
check('its counts: up from the host that made it, down to it - not twice', (nat['up'], nat['down']),
      (4109859292, 1501300))
check('its initiator and responder, its age', (nat['initiator'], nat['responder'], nat['age']),
      ('192.0.2.10', '198.51.100.7', 22 * 60 + 24))
check('the host\'s DNS to the firewall itself is one of its connections',
      ('udp 192.0.2.10:63920 192.0.2.1:53' in found, found.get('udp 192.0.2.10:63920 192.0.2.1:53', {}).get('up')),
      (True, 6667))
check('ICMP and GRE', sorted(k for k in found if k.startswith(('icmp', 'gre'))),
      ['gre 192.0.2.10 198.51.100.9', 'icmp 192.0.2.10:3194 198.51.100.7:8'])
check('age over a day, as pf prints it', found['icmp 192.0.2.10:3194 198.51.100.7:8']['age'], 9 * 3600 + 43 * 60 + 14)

forward, _ = states.parse(TEXT, {'192.0.2.11'})
pf = forward.get('tcp 198.51.100.8:40000 192.0.2.11:80')
check('a port forward to an inside host: one group, the sender made it', (len(forward), pf and pf['initiator'],
                                                                         pf and pf['responder']),
      (1, '198.51.100.8', '192.0.2.11'))
check('its counts as its states hold them: [0] from the sender', (pf['up'], pf['down']), (25000, 600000))

six, _ = states.parse(TEXT, {'2001:db8:1::10'})
check('IPv6: the routed pair one group, the lone query another, route-to on the id line read',
      sorted((k, sorted(v['ids'])) for k, v in six.items()),
      [('tcp 2001:db8:1::10[50000] 2001:db8:ffff::7[443]', ['45fbfe6a00000000/44128282', '46fbfe6a00000000/44128282']),
       ('udp 2001:db8:1::10[24591] 2001:db8:ffff::53[53]', ['55fbfe6a00000000/44128282'])])

none, read = states.parse(TEXT, set())
check('nothing watched: nothing read past a first line', (none, read), ({}, 13))
fw, _ = states.parse(TEXT, {'192.0.2.1'})
check('the firewall\'s own address watched (never so in a run): its rdr, DNS and SSH states',
      sorted(fw), ['tcp 192.0.2.12:40001 192.0.2.1:22', 'udp 192.0.2.10:63920 192.0.2.1:53'])
check('the address a redirect sent to (127.0.0.1) is the stack\'s end, not the one on the wire',
      sorted(states.parse(TEXT, {'127.0.0.1'})[0]), ['tcp 192.0.2.20:40202 127.0.0.1:5140'])

# a state whose two halves were counted apart (the host's own path): the larger each way
split = ('all tcp 198.51.100.7:443 <- 192.0.2.10:50123       ESTABLISHED:ESTABLISHED\n'
         '   age 00:00:10, expires in 23:59:56, 10:10 pkts, 1000:9000 bytes, rule 117\n'
         '   id: 0000000000000001 creatorid: 44128282\n'
         'all tcp 203.0.113.2:61000 (192.0.2.10:50123) -> 198.51.100.7:443       ESTABLISHED:ESTABLISHED\n'
         '   age 00:00:11, expires in 23:59:56, 10:10 pkts, 1200:8000 bytes, rule 108\n'
         '   id: 0000000000000002 creatorid: 44128282\n')
one = states.parse(split, {'192.0.2.10'})[0]['tcp 192.0.2.10:50123 198.51.100.7:443']
check('two states counting apart: the larger each way, the older age', (one['up'], one['down'], one['age']), (1200, 9000, 11))

# the quick look-through gives the same answer as a full read
many = {'192.0.2.%d' % n for n in range(2, 60)} | {'2001:db8:1::10'}
saved = states.QUICK
states.QUICK = 0
full = states.parse(TEXT, many)[0]
states.QUICK = 10 ** 6
quick = states.parse(TEXT, many)[0]
states.QUICK = saved
check('many addresses watched: the same answer with every line split and with the quick look-through',
      (full == quick, len(full)), (True, 9))
check('a watched address that is the start of another\'s text (192.0.2.1 in 192.0.2.10) is not taken for it',
      sorted(states.parse(TEXT, {'192.0.2.1'})[0]) == sorted(fw), True)

# what a cut kills
check('the cut: every state of the host, both of a NAT\'d connection, ICMP and GRE, its DNS to the firewall',
      sorted(states.ids_with(TEXT, {'192.0.2.10'})),
      sorted(['343ffc6a00000000/44128282', 'abe7fe6a00000000/44128282', '2ef2fe6a00000000/44128282',
              '2ff2fe6a00000000/44128282', '61fbfe6a00000000/44128282']))
check('the cut by a translated address alone finds its states (the WAN address: the NAT\'d and the forward\'s)',
      sorted(states.ids_with(TEXT, {'203.0.113.2'})),
      sorted(['2ff2fe6a00000000/44128282', '32fbfe6a00000000/44128282', '75fbfe6a00000000/44128282']))
check('the cut of nothing kills nothing', states.ids_with(TEXT, set()), [])

# a busy firewall's worth, in 26.7's format: read in a moment when few hosts are watched
lines = []
for i in range(50000):
    a, b = '198.51.100.%d' % (i % 250 + 1), '192.0.2.%d' % (i % 200 + 20)
    for head in ('all tcp %s:443 <- %s:%d       ESTABLISHED:ESTABLISHED' % (a, b, 1024 + i),
                 'all tcp 203.0.113.2:%d (%s:%d) -> %s:443       ESTABLISHED:ESTABLISHED' % (1024 + i, b, 1024 + i, a)):
        lines += [head, '   [1000 + 65535] wscale 7  [2000 + 65535] wscale 7',
                  '   age 00:01:00, expires in 23:59:00, 10:20 pkts, %d:%d bytes, rule 12' % (i, 2 * i),
                  '   id: %016x creatorid: 1a2b3c4d' % (2 * i + head.count('->')), '   origif: igb1']
big = '\n'.join(lines) + '\n'
found, read = states.parse(big, {'192.0.2.20'})
check('100,000 states, one host watched: every first line counted, its 250 connections grouped',
      (read, len(found), all(len(c['ids']) == 2 for c in found.values())), (100000, 250, True))

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
