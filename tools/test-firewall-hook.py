#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""The firewall hook in src/etc/inc/plugins.inc.d/quota.inc against the rule-registering object of every
OPNsense it runs on, with PHP and no OPNsense - os-xgs-npu's and os-useridentity's harness: 26.7 to 26.7.2,
26.7.3 to 26.7.8 and 27.1 each name their methods differently, and registerFilterRule() is in all of them.

What is checked: while on, with the plugin's own alias, for each family the pass to DNS on the firewall,
the passes to the web GUI's ports - its port, or 443 or 80 by its protocol, and 80 too while HTTPS
redirects - then the two blocks, from the table and to it, all priority 1, quick, floating; nothing while
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
    """[(priority, family, type, protocol, from, to, port)] of what was registered."""
    if not isinstance(result, dict):
        return result
    return [(c[1][0], c[1][1].get('ipprotocol'), c[1][1].get('type'), c[1][1].get('protocol'), c[1][1].get('from'),
             c[1][1].get('to'), c[1][1].get('to_port')) for c in result['calls']]


if shutil.which('php') is None:
    print('FAIL php is not installed, so the firewall hook cannot be checked')
    sys.exit(1)


def want(ports):
    out = []
    for family in ('inet', 'inet6'):
        out.append((1, family, 'pass', 'tcp/udp', '<quota_over>', '(self)', '53'))
        out += [(1, family, 'pass', 'tcp', '<quota_over>', '(self)', p) for p in ports]
        out.append((1, family, 'block', None, '<quota_over>', None, None))
        out.append((1, family, 'block', None, None, '<quota_over>', None))
    return out


for release, methods in (('26.7', CORE_26_7), ('26.7.3 to 26.7.8', CORE_26_7_3), ('27.1', CORE_27_1)):
    got = hook(methods)
    check('OPNsense %s: DNS and the web GUI (443, and 80 that redirects) let through, then from and to the table blocked, '
          'both families' % release, rules(got), want(['443', '80']))
    if isinstance(got, dict):
        check('OPNsense %s: every rule quick, inbound, floating, described; the hook hands back the object' % release,
              (all(c[1][1].get('quick') is True and c[1][1].get('direction') == 'in' and 'interface' not in c[1][1] and
                   c[1][1].get('descr', '').startswith('Quotas: ') for c in got['calls']), got['same']), (True, True))
        check('OPNsense %s: the passes keep state, the blocks do not ask for it' % release,
              [c[1][1].get('statetype') for c in got['calls']], (['keep', 'keep', 'keep', None, None] * 2))

check('the web GUI on its own port, HTTPS: that port and 80', rules(hook(conf=config(webgui={'protocol': 'https', 'port': '8443'}))),
      want(['8443', '80']))
check('HTTPS with the redirect from 80 turned off: its port alone',
      rules(hook(conf=config(webgui={'protocol': 'https', 'disablehttpredirect': '1'}))), want(['443']))
check('HTTP: 80 alone', rules(hook(conf=config(webgui={'protocol': 'http'}))), want(['80']))
check('a web GUI port that is no port: left out, the rest registered',
      rules(hook(conf=config(webgui={'protocol': 'https', 'port': '0x50', 'disablehttpredirect': '1'}))), want([]))
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
