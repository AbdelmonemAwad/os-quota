#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""What the firewall knows of the hosts around it, for the quotas:

  - its own addresses (ifconfig -a), never counted as a host's and never blocked: a quota naming one, by
    mistake or through a MAC, would otherwise put the firewall's own address in the block table;
  - whether it is a CARP backup (ifconfig -a's carp lines): a backup holds pfsync's copies of the
    master's states, so counting there would count the same traffic again (settled point 15's starred
    choice: the master alone counts and blocks);
  - which addresses each MAC has now (settled point 9's starred choice): OPNsense's own host discovery,
    as configctl hostwatch dump gives it (scripts/interfaces/list_hosts.py -n), newest first, so an
    address another device took since is that device's, and only those seen in the last hour
    (--last-seen-window, in 26.7.9's script): an address no longer used carries nothing to count. Where
    that script cannot be run, or does not know the window, the ARP and neighbour tables themselves
    (arp -an, ndp -an), which hold what is there now.

Each reader takes the program's text, so the tests give them FreeBSD's own output; the functions at the
end ask the programs.
"""

import ipaddress
import json
import re
import subprocess

import settings

IFCONFIG = '/sbin/ifconfig'
ARP = '/usr/sbin/arp'
NDP = '/usr/sbin/ndp'
LIST_HOSTS = '/usr/local/opnsense/scripts/interfaces/list_hosts.py'
SEEN = 3600             # seconds: a MAC's addresses are those host discovery saw in the last hour

HEAD = re.compile(r'^(\S+?):\s+flags=')
CARP = re.compile(r'^\s+carp:\s+(MASTER|BACKUP|INIT)\b')


def run(program, *args):
    """(output, None), or (None, why) when the program cannot be run or fails."""
    try:
        done = subprocess.run([program] + list(args), capture_output=True, text=True, errors='replace', timeout=30)
    except (OSError, subprocess.SubprocessError) as error:
        return None, str(error)
    if done.returncode != 0:
        return None, '%s exited %d' % (program, done.returncode)
    return done.stdout, None


def _interface(words):
    """The address of one inet or inet6 line of ifconfig, written either way it writes them -
    'inet 192.0.2.1 netmask 0xffffff00', 'inet 192.0.2.1/24', 'inet6 fe80::1%em0 prefixlen 64'."""
    text = words[1].split('/')[0].split('%')[0]
    try:
        return ipaddress.ip_address(text).compressed
    except ValueError:
        return None


def own(text):
    """The firewall's own addresses, from ifconfig -a's text."""
    out, dev = set(), None
    for line in (text or '').splitlines():
        head = HEAD.match(line)
        if head:
            dev = head.group(1)
            continue
        words = line.split()
        if dev is None or len(words) < 2 or words[0] not in ('inet', 'inet6'):
            continue
        found = _interface(words)
        if found:
            out.add(found)
    return out


def carp_role(text):
    """'master' when any CARP address of this firewall is master, 'backup' when it has CARP addresses and
    none is, None when it has none."""
    states = [m.group(1) for m in (CARP.match(line) for line in (text or '').splitlines()) if m]
    if not states:
        return None
    return 'master' if 'MASTER' in states else 'backup'


def list_hosts(text):
    """{MAC: [addresses]} of list_hosts.py's JSON (rows of interface, MAC, address; newest first when
    host discovery is the source): each address goes to the MAC of the first row that has it."""
    try:
        rows = json.loads(text).get('rows') or []
    except (ValueError, AttributeError):
        return None
    out, taken = {}, set()
    for row in rows:
        if not isinstance(row, list) or len(row) < 3:
            continue
        found = settings.mac(str(row[1]))
        try:
            address = ipaddress.ip_address(str(row[2]).split('%')[0]).compressed
        except ValueError:
            continue
        if not found or address in taken:
            continue
        taken.add(address)
        out.setdefault(found, []).append(address)
    return out


def arp(text):
    """{MAC: [IPv4 addresses]} of arp -an's text; an entry with no MAC yet, (incomplete), left out."""
    out = {}
    for line in (text or '').splitlines():
        found = re.match(r'^\S+ \(([0-9.]+)\) at (\S+) ', line)
        if found and settings.mac(found.group(2)):
            out.setdefault(settings.mac(found.group(2)), []).append(found.group(1))
    return out


def ndp(text):
    """{MAC: [IPv6 addresses]} of ndp -an's text; the header and entries with no MAC left out."""
    out = {}
    for line in (text or '').splitlines():
        words = line.split()
        if len(words) < 2 or not settings.mac(words[1]):
            continue
        try:
            where = ipaddress.ip_address(words[0].split('%')[0])
        except ValueError:
            continue
        out.setdefault(settings.mac(words[1]), []).append(where.compressed)
    return out


def addresses_of(macs, table, mine):
    """{MAC: set of addresses} for the MACs asked about: those the table gives each, usable as a host's
    (settings.usable) and not the firewall's own."""
    return {m: {a for a in table.get(m, []) if settings.usable(a) and a not in mine} for m in macs}


def neighbours():
    """({MAC: [addresses]}, where from, error or None): host discovery's rows, or the ARP and neighbour
    tables when list_hosts.py cannot be run."""
    text, error = run('/usr/local/bin/python3', LIST_HOSTS, '-n', '--last-seen-window', str(SEEN))
    found = list_hosts(text) if text is not None else None
    if found is not None:
        return found, 'hostwatch', None
    table = arp(run(ARP, '-an')[0])
    for key, value in ndp(run(NDP, '-an')[0]).items():
        table.setdefault(key, []).extend(value)
    return table, 'arp-ndp', error or 'list_hosts.py gave no answer that could be read'


def interfaces():
    """(own addresses, CARP role, error or None) as ifconfig -a gives them now."""
    text, error = run(IFCONFIG, '-a')
    return own(text), carp_role(text), error
