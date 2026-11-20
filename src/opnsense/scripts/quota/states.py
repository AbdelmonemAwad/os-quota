#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""pf's states, read as the quotas count them (settled point 1: from the states, the only count that holds
what a connection in hardware carried - os-xgs-npu's "Count hardware traffic in pf" adds the
coprocessor's counts to them, and to no table entry: phase 0's A7).

`pfctl -vvs state` - -vv, for the state's id and its creator - writes each state as (pf_print_state.c,
FreeBSD 15.1; seen on both appliances in phase 0):

    all tcp 198.51.100.7:443 <- 192.0.2.10:50123       ESTABLISHED:ESTABLISHED
       [3702501927 + 28800] wscale 7  [3264724699 + 65664] wscale 7
       age 00:22:24, expires in 23:59:56, 386:385 pkts, 479381:15436 bytes, rule 117, rlabel ...
       id: 2ef2fe6a00000000 creatorid: 44128282
       origif: igb1

The first word is the interface, or "all" for a floating state; IPv4 ends are written address:port,
IPv6 ends address[port]; a translated end has the other form after it in brackets. On a "<-" line - a
state made by a packet coming in - the bare ends are the stack's side, and the second is the one that
made it; on a "->" line the stack's side is the end in brackets where there is one, and the first is
the one that made it. Byte counts are [0] from the one that made the state, [1] back to it.

ONE CONNECTION, ONE COUNT. A routed connection has a state on each interface it crosses, each holding
the whole connection (phase 0: the log of 2026-10-19; A2 under outbound NAT), so its states are grouped
by protocol and stack-side ends, which are the same on all of them, and the group counts once: its
largest count each way.

Only the states with an end among the addresses watched are read past their first line: a firewall with
100,000 states reads them in a fraction of the time (phase 0's A9).
"""

import re

AGE = re.compile(r'\bage (\d+):(\d+):(\d+)')
BYTES = re.compile(r'(\d+):(\d+) bytes')
STATE_ID = re.compile(r'^\s+id: ([0-9a-fA-F]+) creatorid: ([0-9a-fA-F]+)')
# Up to this many addresses watched, a state's first line is looked through for them as text before it
# is split: most of a busy firewall's states are not a watched host's.
QUICK = 32


def address(end):
    """The address of an end as pf writes it: 'a.b.c.d:port', 'a.b.c.d', 'x::y[port]' or 'x::y'."""
    end = end.strip('()')
    if '[' in end:
        return end.split('[', 1)[0].lower()
    if end.count(':') == 1:
        return end.split(':', 1)[0]
    return end.lower()


def header(line):
    """(protocol, initiator end, responder end, every address on the line) of a state's first line, or
    None for a line that is not one."""
    words = line.split()
    if len(words) < 6:
        return None
    for arrow in range(3, len(words) - 2):
        if words[arrow] in ('->', '<-'):
            break
    else:
        return None
    left, right = words[2:arrow], words[arrow + 1:-1]
    if not 1 <= len(left) <= 2 or not 1 <= len(right) <= 2:
        return None
    out = words[arrow] == '->'

    def stack(side):
        if out and len(side) == 2:
            return side[1].strip('()')
        return side[0]

    a, b = stack(left), stack(right)
    initiator, responder = (a, b) if out else (b, a)
    every = {address(w) for w in left + right}
    return words[1], initiator, responder, every


def parse(text, watched):
    """({key: connection}, states read) for the connections with an end whose address is in watched.

    A connection is {'proto', 'initiator', 'responder' (its stack-side ends' addresses), 'ids' (set of
    'id/creatorid'), 'up', 'down' (bytes from and to the initiator, the largest of its states), 'age'
    (seconds, its oldest state's)}; its key is the protocol and the two ends with their ports, the same
    on each of its states."""
    found = {}
    count = 0
    cur = None
    # a few hosts watched: a line that holds none of their addresses as text is passed over unsplit
    quick = watched if len(watched) <= QUICK else None
    for line in (text or '').splitlines():
        if not line:
            continue
        if not line[0].isspace():
            count += 1
            cur = None
            if quick is not None and not any(w in line for w in quick):
                continue
            head = header(line)
            if head is None:
                continue
            proto, ini, res, _ = head
            ini_addr, res_addr = address(ini), address(res)
            if ini_addr not in watched and res_addr not in watched:
                continue
            key = '%s %s %s' % (proto, ini, res)
            cur = found.setdefault(key, {'proto': proto, 'initiator': ini_addr, 'responder': res_addr,
                                         'ids': set(), 'up': 0, 'down': 0, 'age': 0})
            continue
        if cur is None:
            continue
        if ' bytes' in line:
            age = AGE.search(line)
            if age:
                cur['age'] = max(cur['age'], int(age.group(1)) * 3600 + int(age.group(2)) * 60 + int(age.group(3)))
            counted = BYTES.search(line)
            if counted:
                cur['up'] = max(cur['up'], int(counted.group(1)))
                cur['down'] = max(cur['down'], int(counted.group(2)))
            continue
        ident = STATE_ID.match(line)
        if ident:
            cur['ids'].add('%s/%s' % (ident.group(1).lower(), ident.group(2).lower()))
    return found, count


def ids_with(text, addresses):
    """['id/creatorid'] of every state with any of its addresses - either end, translated or not - in
    addresses: what a cut kills, as OPNsense's own Sessions page kills a state (pfctl -k id -k id/creator)."""
    out = []
    hit = False
    quick = addresses if len(addresses) <= QUICK else None
    for line in (text or '').splitlines():
        if not line:
            continue
        if not line[0].isspace():
            hit = False
            if quick is not None and not any(w in line for w in quick):
                continue
            head = header(line)
            hit = head is not None and bool(head[3] & addresses)
            continue
        if hit:
            ident = STATE_ID.match(line)
            if ident:
                out.append('%s/%s' % (ident.group(1).lower(), ident.group(2).lower()))
                hit = False
    return out
