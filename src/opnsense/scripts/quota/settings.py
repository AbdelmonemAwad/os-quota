#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""Quotas' settings, read straight out of config.xml by element name: the plugin's own
(models/OPNsense/Quota/Quota.xml - the names here are not free), the alias it owns in Firewall:
Aliases, and what it reads of os-xgs-npu's XGS: Settings - the cut list, and whether the hardware's
counts are given to pf.

Nothing here writes. A config.xml that cannot be read gives the defaults with read False, and every
caller does nothing it would regret on them: the plugin is off by default.

    settings.py enabled    {"enabled": ..., "read": ...} - for the installer and the package's scripts
"""

import ipaddress
import json
import re
import sys
import xml.etree.ElementTree as ET

CONFIG = '/conf/config.xml'

# A minute of use is a minute in which the host moved more than this many kilobytes (1 KB = 1,000
# bytes), both ways together. PROVISIONAL: the plan sets it from a lab measurement of an idle real
# device on both appliances, which has not been taken yet (phase 0's A11 machine had no way out, so it
# sent nothing). Settings' "Minute of use above" is empty unless the owner types a value, and empty is
# this number - so a release that changes it changes it on every firewall left at the plugin's own value.
# forms/general.xml's help names it.
MINUTE_KB = 100

# The pf table of the hosts over their quota: an External alias in Firewall: Aliases, written by
# aliases.php, so XGS: Settings' cut list can name it (settled point 5).
ALIAS = 'quota_over'
DESCRIPTION = 'Quotas: hosts over their quota'
OWNED = 'Quotas:'

CYCLES = ('day', 'week', 'month')
MB = 1000 * 1000

MAC = re.compile(r'^[0-9a-f]{2}([:-]?)[0-9a-f]{2}(\1[0-9a-f]{2}){4}$')


def _text(node, tag, default=''):
    if node is None:
        return default
    found = node.findtext(tag)
    return default if found is None else found.strip()


def _int(text, default, low, high):
    try:
        value = int(text)
    except (TypeError, ValueError):
        return default
    return value if low <= value <= high else default


def mac(text):
    """The MAC in one form - six pairs of lower-case digits joined by colons - or None."""
    text = (text or '').strip().lower()
    if not MAC.match(text):
        return None
    digits = re.sub(r'[:-]', '', text)
    return ':'.join(digits[i:i + 2] for i in range(0, 12, 2))


def usable(address):
    """Whether an address can be a host's: not unspecified, loopback, link-local, multicast or the IPv4
    broadcast - those are never one device's traffic through the firewall."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        return False
    # IPv4: the broadcast, and 0.0.0.0/8 - "this network", never a host's own source
    return not (ip.version == 4 and (int(ip) == 0xffffffff or int(ip) >> 24 == 0))


def host(text):
    """What a quota's Host names: ('address', the address as pf prints it) for an IPv4 or IPv6 address,
    ('mac', the MAC in lower case with colons - 02:00:00:aa:bb:cc) for a MAC, None for anything else.
    Quota.php refuses the same."""
    text = (text or '').strip()
    found = mac(text)
    if found:
        first = int(found[:2], 16)
        if found in ('00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff') or first & 1:
            return None
        return ('mac', found)
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if not usable(str(ip)):
        return None
    return ('address', ip.compressed)


def quota_rows(root):
    """The quota rows, each with its uuid, in config order; a row the scripts cannot read is kept with
    host None so the page can say so."""
    out = []
    for node in root.findall('OPNsense/Quota/quotas/quota'):
        volume = _int(_text(node, 'volume'), 0, 1, 1000000000)
        minutes = _int(_text(node, 'minutes'), 0, 1, 44640)
        cycle = _text(node, 'cycle', 'day')
        out.append({
            'uuid': node.get('uuid') or '',
            'enabled': _text(node, 'enabled', '1') == '1',
            'host_text': _text(node, 'host'),
            'host': host(_text(node, 'host')),
            'volume': volume * MB if volume else None,
            'minutes': minutes or None,
            'cycle': cycle if cycle in CYCLES else 'day',
            'description': _text(node, 'description'),
        })
    return out


def read(path=None):
    out = {
        'read': False, 'enabled': False, 'minute_bytes': MINUTE_KB * 1000, 'quotas': [],
        'xgs': False, 'cut_lists': [], 'count_to_pf': None, 'cut_in_hardware': None, 'cut_added': [],
    }
    try:
        root = ET.parse(path or CONFIG).getroot()
    except (OSError, ET.ParseError):
        return out
    out['read'] = True
    general = root.find('OPNsense/Quota/general')
    if general is not None:
        out['enabled'] = _text(general, 'enabled', '0') == '1'
        # empty, or nothing there: the plugin's own value
        out['minute_bytes'] = _int(_text(general, 'minute_threshold'), MINUTE_KB, 0, 1000000) * 1000
        out['cut_added'] = [u for u in _text(general, 'cut_added').split(',') if u.strip()]
    out['quotas'] = quota_rows(root)
    xgs = root.find('OPNsense/XGS/general')
    out['xgs'] = xgs is not None
    if xgs is not None:
        out['cut_lists'] = [u.strip() for u in _text(xgs, 'cut_lists').split(',') if u.strip()]
        out['count_to_pf'] = _text(xgs, 'count_to_pf', '1') != '0'
        out['cut_in_hardware'] = _text(xgs, 'cut_in_hardware', '1') != '0'
    return out


def alias(path=None):
    """The alias named quota_over in Firewall: Aliases: {'uuid', 'enabled', 'type', 'ours'}, or None when
    there is none. It is the plugin's when its description says so (aliases.php writes it)."""
    try:
        root = ET.parse(path or CONFIG).getroot()
    except (OSError, ET.ParseError):
        return None
    for node in root.findall('OPNsense/Firewall/Alias/aliases/alias'):
        if _text(node, 'name') != ALIAS:
            continue
        return {
            'uuid': node.get('uuid') or '',
            'enabled': _text(node, 'enabled', '1') == '1',
            'type': _text(node, 'type'),
            'ours': _text(node, 'description').startswith(OWNED),
        }
    return None


def main(argv):
    if argv[1:2] == ['enabled']:
        conf = read()
        print(json.dumps({'enabled': conf['enabled'], 'read': conf['read']}))
        return 0
    print('usage: settings.py enabled', file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
