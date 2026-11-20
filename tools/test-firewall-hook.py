#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""The firewall hook in src/etc/inc/plugins.inc.d/quota.inc against the rule-registering object of every
OPNsense it runs on, with PHP and no OPNsense - os-xgs-npu's and os-useridentity's harness: 26.7 to 26.7.2,
26.7.3 to 26.7.8 and 27.1 each name their methods differently, and registerFilterRule() is in all of them.

What is checked: while on, with the plugin's own alias, for each family nothing but blocks, all priority
1, quick, inbound, floating: from the table to everything past the firewall; to the firewall itself every
TCP port but DNS's and the web GUI's - its port, or 443 or 80 by its protocol, and 80 too while HTTPS
redirects - every UDP port but DNS's, ICMP and the tunnels' protocols; and to the table. Then what those
rules do, by pf's first quick match, to a probe each way: what a host over its quota sends past the
firewall, to the firewall's other ports and protocols and to it from outside is blocked here, while DNS and
the web GUI on the firewall are not decided here at all - core's anti-lockout and the owner's own rules
decide them, as before the host went over - and a host under its quota is never matched. Nothing while
off, with no alias, an alias of that name that is the owner's, one switched off or not External, or no
Alias model at all; an object that refuses a rule leaves the hook returning, not stopping the reload
(os-xgs-npu issue 969); and the hook calls by name only methods every one of them has.

A refused rule is logged with syslog() as the hook does at run time, so a run of this leaves a "quota: ..."
line in the system log of the machine it runs on.

    python3 tools/test-firewall-hook.py"""
import json
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(ROOT, 'src', 'etc', 'inc', 'plugins.inc.d', 'quota.inc')

# What OPNsense\Firewall\Plugin offers for registering rules, by release (os-xgs-npu's reading of
# opnsense/core's Plugin.php at the tags 26.7, 26.7.3 and 26.7.8; 27.1 is 26.7.8 without the methods its
# source marks "backwards glue to be removed in 27.1").
CORE_26_7 = ['registerAnchor', 'registerFilterRule', 'registerForwardRule', 'registerDNatRule',
             'registerSNatRule', 'registerNptRule', 'registerTable']
CORE_26_7_3 = CORE_26_7 + ['registerDestinationNatRule', 'registerStaticNatRule', 'registerSourceNatRule']
CORE_27_1 = [m for m in CORE_26_7_3 if m not in ('registerForwardRule', 'registerDNatRule', 'registerSNatRule')]

HARNESS = r'''
$c = json_decode($argv[2], true);
$config = $c['config'];
if ($c['aliases'] !== null) {
    eval('namespace OPNsense\Firewall; class Alias { public $aliases; public function __construct() {
        $rows = ' . var_export($c['aliases'], true) . ';
        $this->aliases = (object)["alias" => new class($rows) { private $r; public function __construct($r) { $this->r = $r; }
            public function iterateItems() { foreach ($this->r as $i => $row) { yield "u" . $i => (object)$row; } } }]; } }');
}
$body = '';
foreach ($c['methods'] as $m) {
    $body .= "public function $m(...\$a) { " . ($c['refuse'] === $m ? "throw new RuntimeException('refused'); " : '')
        . "\$this->calls[] = ['$m', \$a]; }\n";
}
eval("class FakePlugin { public \$calls = [];\n$body}");
include $argv[1];
$fw = new FakePlugin();
$out = quota_firewall($fw);
echo json_encode(['same' => $out === $fw, 'calls' => $fw->calls]);
'''

failures = 0
checks = 0


def check(name, got, want):
    global failures, checks
    checks += 1
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


OURS = [{'name': 'quota_over', 'description': 'Quotas: hosts over their quota', 'enabled': '1', 'type': 'external'},
        {'name': 'mine', 'description': 'a list', 'enabled': '1', 'type': 'host'}]


def config(enabled='1', webgui=None):
    out = {'OPNsense': {'Quota': {'general': {'enabled': enabled}}}}
    out['system'] = {'webgui': webgui if webgui is not None else {'protocol': 'https'}}
    return out


def hook(methods=CORE_26_7_3, conf=None, aliases=OURS, refuse=None):
    case = json.dumps({'methods': methods, 'config': conf or config(), 'refuse': refuse, 'aliases': aliases})
    out = subprocess.run(['php', '-r', HARNESS, '--', HOOK, case], capture_output=True, text=True)
    if out.returncode != 0 or not out.stdout.startswith('{'):
        return 'php failed: ' + (out.stderr or out.stdout).strip()[:300]
    return json.loads(out.stdout)


def rules(result):
    """[(priority, family, type, protocol, from, to, port)] of what was registered; a negated 'to' as '!' and
    the address."""
    if not isinstance(result, dict):
        return result
    return [(c[1][0], c[1][1].get('ipprotocol'), c[1][1].get('type'), c[1][1].get('protocol'), c[1][1].get('from'),
             ('!' if c[1][1].get('to_not') else '') + c[1][1]['to'] if c[1][1].get('to') else None,
             c[1][1].get('to_port')) for c in result['calls']]


# pf's numbers for the protocols the rules name
PROTO = {'tcp': 6, 'udp': 17, 'icmp': 1, 'ipv6-icmp': 58}
OVER = {'inet': '192.0.2.50', 'inet6': '2001:db8:1::50'}       # in the table
UNDER = {'inet': '192.0.2.60', 'inet6': '2001:db8:1::60'}      # not
SELF = {'inet': '192.0.2.1', 'inet6': '2001:db8:1::1'}          # one of the firewall's own addresses
AWAY = {'inet': '198.51.100.7', 'inet6': '2001:db8:2::7'}       # past the firewall


def verdict(result, family, proto, src, dst, port=None):
    """What the hook's rules do to an inbound packet, by pf's first quick match: 'block', 'pass', or
    'through' when none of them matches it and the rules after them decide."""
    table = {OVER['inet'], OVER['inet6']}
    mine = {SELF['inet'], SELF['inet6']}
    for c in result['calls']:
        r = c[1][1]
        if r.get('ipprotocol') != family or r.get('direction') != 'in' or r.get('quick') is not True:
            continue
        if r.get('from') == '<quota_over>' and src not in table:
            continue
        to = r.get('to')
        if to == '(self)' and (dst in mine) == bool(r.get('to_not')):
            continue
        if to == '<quota_over>' and dst not in table:
            continue
        want = r.get('protocol')
        if want is not None and proto not in ((6, 17) if want == 'tcp/udp' else (int(PROTO.get(want, want)),)):
            continue
        if r.get('to_port') is not None:
            low, _, high = r['to_port'].partition(':')
            if port is None or not int(low) <= port <= int(high or low):
                continue
        return r.get('type')
    return 'through'


if shutil.which('php') is None:
    print('FAIL php is not installed, so the firewall hook cannot be checked')
    sys.exit(1)


def want(tcp):
    """The rules registered, for the TCP port ranges left after DNS's and the web GUI's."""
    out = []
    for family in ('inet', 'inet6'):
        out.append((1, family, 'block', None, '<quota_over>', '!(self)', None))
        out += [(1, family, 'block', 'tcp', '<quota_over>', '(self)', p) for p in tcp]
        out += [(1, family, 'block', 'udp', '<quota_over>', '(self)', p) for p in ('1:52', '54:65535')]
        out += [(1, family, 'block', p, '<quota_over>', '(self)', None)
                for p in ('icmp' if family == 'inet' else 'ipv6-icmp', '4', '41', '47', '50', '51')]
        out.append((1, family, 'block', None, None, '<quota_over>', None))
    return out


HTTPS = ['1:52', '54:79', '81:442', '444:65535']
for release, methods in (('26.7', CORE_26_7), ('26.7.3 to 26.7.8', CORE_26_7_3), ('27.1', CORE_27_1)):
    got = hook(methods)
    check('OPNsense %s: blocks only - past the firewall, its other TCP and UDP ports, ICMP and tunnels, and to the '
          'table - both families' % release, rules(got), want(HTTPS))
    if isinstance(got, dict):
        check('OPNsense %s: every rule a block, quick, inbound, floating, described; the hook hands back the object'
              % release,
              (all(c[1][1].get('type') == 'block' and c[1][1].get('quick') is True and c[1][1].get('direction') == 'in'
                   and 'interface' not in c[1][1] and c[1][1].get('descr', '').startswith('Quotas: ')
                   for c in got['calls']), got['same']), (True, True))
        check('OPNsense %s: no rule keeps state, none passes anything' % release,
              [c[1][1].get('statetype') for c in got['calls'] if 'statetype' in c[1][1]] +
              [c[1][1].get('type') for c in got['calls'] if c[1][1].get('type') != 'block'], [])

# What the rules do, by pf's first quick match: the GUI on 443 with 80 redirecting
got = hook()
TCP, UDP, ICMP = 6, 17, 1
for family in ('inet', 'inet6'):
    icmp = ICMP if family == 'inet' else 58
    over, under, me, away = OVER[family], UNDER[family], SELF[family], AWAY[family]
    check('%s: a host over its quota - everything past the firewall blocked here, whatever it is' % family,
          [verdict(got, family, p, over, away, port) for p, port in ((TCP, 443), (TCP, 53), (UDP, 53), (UDP, 443),
                                                                   (icmp, None), (47, None), (50, None))],
          ['block'] * 7)
    check('%s: DNS and the web GUI on the firewall not decided here - left to core\'s anti-lockout and the '
          'owner\'s rules, as before it went over' % family,
          [verdict(got, family, p, over, me, port) for p, port in ((TCP, 53), (UDP, 53), (TCP, 443), (TCP, 80))],
          ['through'] * 4)
    check('%s: every other port of the firewall blocked here, the edges of each range among them' % family,
          [verdict(got, family, TCP, over, me, port) for port in (1, 22, 52, 54, 79, 81, 442, 444, 3128, 8443, 65535)] +
          [verdict(got, family, UDP, over, me, port) for port in (1, 52, 54, 123, 500, 4500, 51820, 65535)],
          ['block'] * 19)
    check('%s: ICMP and the tunnels\' protocols to the firewall blocked here' % family,
          [verdict(got, family, p, over, me) for p in (icmp, 4, 41, 47, 50, 51)], ['block'] * 6)
    check('%s: every new connection to the host blocked here, from outside and from beside it' % family,
          [verdict(got, family, p, src, over, port) for p, src, port in ((TCP, away, 443), (UDP, under, 53),
                                                                        (icmp, under, None))],
          ['block'] * 3)
    check('%s: a host under its quota - nothing here matches it' % family,
          [verdict(got, family, p, under, dst, port) for p, dst, port in ((TCP, away, 443), (TCP, me, 22), (UDP, me, 123),
                                                                         (icmp, me, None), (47, me, None))],
          ['through'] * 5)

GUI_8443 = ['1:52', '54:79', '81:8442', '8444:65535']
check('the web GUI on its own port, HTTPS: that port and 80 left out of the TCP blocks',
      rules(hook(conf=config(webgui={'protocol': 'https', 'port': '8443'}))), want(GUI_8443))
got = hook(conf=config(webgui={'protocol': 'https', 'port': '8443', 'disablehttpredirect': '1'}))
check('HTTPS on 8443, the redirect from 80 turned off: 8443 left to the owner\'s rules, 443 and 80 blocked here',
      [verdict(got, 'inet', 6, OVER['inet'], SELF['inet'], port) for port in (8443, 443, 80)],
      ['through', 'block', 'block'])
check('HTTPS with the redirect from 80 turned off: its port alone',
      rules(hook(conf=config(webgui={'protocol': 'https', 'disablehttpredirect': '1'}))),
      want(['1:52', '54:442', '444:65535']))
check('HTTP: 80 alone', rules(hook(conf=config(webgui={'protocol': 'http'}))), want(['1:52', '54:79', '81:65535']))
check('a web GUI port that is no port: left out, DNS\'s alone kept',
      rules(hook(conf=config(webgui={'protocol': 'https', 'port': '0x50', 'disablehttpredirect': '1'}))),
      want(['1:52', '54:65535']))
check('the web GUI on 54, beside DNS: no empty range between them',
      rules(hook(conf=config(webgui={'protocol': 'https', 'port': '54', 'disablehttpredirect': '1'}))),
      want(['1:52', '55:65535']))
check('the web GUI on 55: the one port between DNS and it blocked alone, as 54',
      rules(hook(conf=config(webgui={'protocol': 'https', 'port': '55', 'disablehttpredirect': '1'}))),
      want(['1:52', '54', '56:65535']))
check('the web GUI on 65535: nothing past it',
      rules(hook(conf=config(webgui={'protocol': 'https', 'port': '65535', 'disablehttpredirect': '1'}))),
      want(['1:52', '54:65534']))
ports = [c[1][1]['to_port'] for c in hook()['calls'] if c[1][1].get('to_port') is not None]
check('every port as OPNsense\'s FilterRule takes one: a port or one range of 1 to 65535, low to high',
      [p for p in ports if not re.match(r'^\d+(:\d+)?$', p) or
       not 1 <= int(p.split(':')[0]) <= int(p.split(':')[-1]) <= 65535], [])
check('off: no rule', rules(hook(conf=config(enabled='0'))), [])
check('no setting at all (a fresh install): no rule', rules(hook(conf={'system': {}})), [])
check('the alias not made yet: no rule', rules(hook(aliases=[OURS[1]])), [])
check('an alias of that name that is the owner\'s: no rule - its addresses are his',
      rules(hook(aliases=[dict(OURS[0], description='my own list')])), [])
check('the plugin\'s alias switched off: no rule', rules(hook(aliases=[dict(OURS[0], enabled='0')])), [])
check('the plugin\'s alias no longer External: no rule', rules(hook(aliases=[dict(OURS[0], type='host')])), [])
check('no Alias model at all: no rule, the reload not stopped', (rules(hook(aliases=None)),), ([],))
got = hook(refuse='registerFilterRule')
check('a refused rule does not stop the reload', (got['same'], got['calls']) if isinstance(got, dict) else got, (True, []))

with open(HOOK, encoding='utf-8') as f:
    source = f.read()
named = sorted(set(re.findall(r'\$fw->(\w+)\s*\(', source)))
everywhere = sorted(set(CORE_26_7) & set(CORE_26_7_3) & set(CORE_27_1))
check('the hook calls by name only methods every OPNsense has', [m for m in named if m not in everywhere], [])

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
