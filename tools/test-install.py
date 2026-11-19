#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""The installer, the removal, the package's three scripts, place-menu.sh and the boot's hook, run in a
temporary root.

As os-useridentity's test: the scripts are run with sh from a copy of the repository in which their
absolute paths are moved into the temporary root - /usr/local, /var/db/os-quota, PHP's /var/lib/php/tmp,
the caches in /tmp, /conf/config.xml, /sbin/pfctl, /bin/pkill - and stand-ins answer for what only a
firewall has: service, configctl, pfctl and pkill, each writing down how it was called (pkill kills
nothing here). Two things FreeBSD does otherwise are bridged in the copy: BSD's `cp -R dir/` copies what
dir holds, written `dir/.` for GNU's cp; BSD's `mktemp -t prefix` takes a prefix, which a stand-in gives
GNU's mktemp; and install's -o root -g wheel, which a test run by anyone cannot take, is left out by a
stand-in.

What is checked is what the scripts do: which files are laid down with which modes, where the menu goes,
that nothing is copied when a file has a syntax error, the page's Apply done in its order - off by
default, so the table emptied before the alias and the table taken out of pf after the filter; on, a read
after the filter - the table emptied and the alias taken out before the files go, the table taken out of
pf once its alias is gone and no rule holds it, nothing of the plugin left, nothing done by the old
package's pre-deinstall in an upgrade, and the boot's hook running one read, or nothing once the plugin is
gone.

    python3 tools/test-install.py"""
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = ['install/install.sh', 'install/uninstall.sh', 'pkg/post-install.sh', 'pkg/pre-deinstall.sh',
           'pkg/post-deinstall.sh', 'src/opnsense/scripts/quota/place-menu.sh', 'src/opnsense/scripts/quota/settings.py',
           'src/etc/rc.syshook.d/start/70-quota']
LOCAL = '/usr/local'
MENU = '/usr/local/opnsense/mvc/app/models/OPNsense/Quota/Menu/Menu.xml'
XGS = '/usr/local/opnsense/mvc/app/models/OPNsense/XGS/Menu/Menu.xml'
HOOK = '/usr/local/etc/inc/plugins.inc.d/quota.inc'
BOOT = '/usr/local/etc/rc.syshook.d/start/70-quota'
STATE = '/var/db/os-quota'
CACHES = ['/var/lib/php/tmp/opnsense_menu_cache.xml', '/var/lib/php/tmp/opnsense_acl_cache.json',
          '/tmp/opnsense_menu_cache.xml', '/tmp/opnsense_acl_cache.json']
COMMIT = '0123456789abcdef0123456789abcdef01234567'
ON = '<opnsense><OPNsense><Quota><general><enabled>1</enabled></general></Quota></OPNsense></opnsense>'
OFF = '<opnsense><system/></opnsense>'
APPLY_OFF = ['configctl quota flush hook=yes', 'configctl quota apply hook=yes', 'configctl filter reload skip_alias hook=yes',
             'configctl cron restart hook=yes', 'configctl quota gone hook=yes']
APPLY_ON = ['configctl quota apply hook=yes', 'configctl filter reload skip_alias hook=yes', 'configctl cron restart hook=yes',
            'configctl quota account hook=yes']

failures = 0
checks = 0


def check(name, got, want):
    global failures, checks
    checks += 1
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


class Box:
    """A temporary root, a copy of the repository whose scripts work in it, and the stand-ins."""

    def __init__(self, tmp):
        self.fake = os.path.join(tmp, 'root')
        self.repo = os.path.join(tmp, 'repo')
        self.bin = os.path.join(tmp, 'bin')
        self.calls = os.path.join(tmp, 'calls')
        self.tables = os.path.join(tmp, 'pf-tables')
        os.makedirs(self.fake)
        os.makedirs(self.bin)
        shutil.copytree(ROOT, self.repo, ignore=shutil.ignore_patterns('.git', '__pycache__', '*.pyc'))
        # every file as a checkout has it, not runnable: the scripts set what must be
        for base, _, files in os.walk(self.repo):
            for name in files:
                os.chmod(os.path.join(base, name), 0o644)
        for script in SCRIPTS:
            path = os.path.join(self.repo, script)
            text = open(path, encoding='utf-8').read()
            # a path where one starts, not one inside another (/var/lib/php/tmp/ holds /tmp/ too)
            text = re.sub(r'(?<![\w/.-])(/usr/local/|/var/lib/php/tmp/|/tmp/opnsense_|/sbin/pfctl|/var/db/os-quota|'
                          r'/conf/config\.xml|/bin/pkill)', lambda m: self.fake + m.group(1), text)
            text = text.replace('cp -R "${HERE}/src/" ', 'cp -R "${HERE}/src/." ')
            with open(path, 'w', encoding='utf-8', newline='\n') as handle:
                handle.write(text)
        hook = self.fake + HOOK
        log = self.calls
        self.stub('configctl', 'echo "configctl $* hook=$([ -f %s ] && echo yes || echo no)" >> %s\necho OK' % (hook, log))
        self.stub('service', 'echo "service $*" >> %s' % log)
        self.stub('mktemp', 'if [ "$1" = -d ] && [ "$2" = -t ]; then exec /usr/bin/env mktemp -d '
                            '"${TMPDIR:-/tmp}/$3.XXXXXX"; fi\nexec /usr/bin/env mktemp "$@"', real='mktemp')
        self.stub('install', 'a=""\nwhile [ $# -gt 0 ]; do case "$1" in -o|-g) shift 2 ;; *) a="$a \'$1\'"; shift ;; '
                             'esac; done\neval exec /usr/bin/env install $a', real='install')
        os.makedirs(self.fake + '/sbin')
        self.write(self.fake + '/sbin/pfctl', '#!/bin/sh\necho "pfctl $*" >> %s\n'
                   'case "$*" in "-v -s Tables") cat %s 2>/dev/null ;; esac\n' % (log, self.tables), 0o755)
        os.makedirs(self.fake + '/bin')
        self.write(self.fake + '/bin/pkill', '#!/bin/sh\necho "pkill $*" >> %s\nexit 1\n' % log, 0o755)
        os.makedirs(self.fake + '/conf')
        self.config(OFF)

    def config(self, text):
        self.write(self.fake + '/conf/config.xml', text)

    def stub(self, name, body, real=None):
        path = os.path.join(self.bin, name)
        if real:
            # the stand-in must not find itself: the real one is looked for past this directory
            body = body.replace('/usr/bin/env %s' % real, shutil.which(real, path=os.defpath) or '/usr/bin/' + real)
        self.write(path, '#!/bin/sh\n' + body + '\n', 0o755)

    @staticmethod
    def write(path, text, mode=0o644):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8', newline='\n') as handle:
            handle.write(text)
        os.chmod(path, mode)

    def run(self, script, *args, env=None):
        return self.sh(os.path.join(self.repo, script), *args, env=env)

    def sh(self, path, *args, env=None):
        environ = dict(os.environ, PATH=self.bin + os.pathsep + os.environ.get('PATH', ''),
                       TMPDIR=os.path.dirname(self.fake))
        environ.update(env or {})
        done = subprocess.run(['sh', path] + list(args), env=environ, capture_output=True, text=True, timeout=300)
        return done.returncode, done.stdout + done.stderr

    def called(self, prefix=''):
        try:
            return [c for c in open(self.calls, encoding='utf-8').read().splitlines() if c.startswith(prefix)]
        except OSError:
            return []

    def forget(self):
        if os.path.exists(self.calls):
            os.remove(self.calls)

    def plugin_files(self):
        """Every file under the root that the plugin has a hand in."""
        out = []
        for base, _, files in os.walk(self.fake):
            for name in files:
                path = os.path.join(base, name)[len(self.fake):]
                if 'quota' in path.lower():
                    out.append(path)
        return sorted(out)

    def mode(self, path):
        return stat.S_IMODE(os.stat(self.fake + path).st_mode)

    def read(self, path):
        try:
            return open(self.fake + path, encoding='utf-8').read()
        except OSError:
            return None

    def python3(self):
        """/usr/local/bin/python3 of the root: the test's own python3."""
        self.write(self.fake + '/usr/local/bin/python3', '#!/bin/sh\nexec %s "$@"\n' % sys.executable, 0o755)


def source_files():
    out = []
    for base, _, files in os.walk(os.path.join(ROOT, 'src')):
        for name in files:
            if name.endswith('.pyc') or '__pycache__' in base:
                continue
            out.append(LOCAL + os.path.join(base, name)[len(os.path.join(ROOT, 'src')):].replace(os.sep, '/'))
    return sorted(out)


with tempfile.TemporaryDirectory() as tmp:
    box = Box(tmp)
    menu_own = open(os.path.join(ROOT, 'src/opnsense/scripts/quota/menu/own.xml'), encoding='utf-8').read()
    menu_xgs = open(os.path.join(ROOT, 'src/opnsense/scripts/quota/menu/xgs.xml'), encoding='utf-8').read()
    place = 'src/opnsense/scripts/quota/place-menu.sh'

    # place-menu.sh: XGS where os-xgs-npu's menu is, Firewall where it is not
    for cache in CACHES:
        box.write(box.fake + cache, 'cached')
    rc, out = box.run(place)
    check('place-menu.sh without os-xgs-npu: own, the Firewall menu file', (rc, out.strip(), box.read(MENU)),
          (0, 'own', menu_own))
    check('place-menu.sh: the menu caches cleared', [c for c in CACHES[::2] if os.path.exists(box.fake + c)], [])
    box.write(box.fake + XGS, '<menu/>')
    rc, out = box.run(place)
    check('place-menu.sh with os-xgs-npu: xgs, the XGS menu file, order 62', (rc, out.strip(), box.read(MENU),
                                                                             'order="62"' in menu_xgs), (0, 'xgs', menu_xgs, True))
    os.remove(box.fake + XGS)
    shutil.rmtree(box.fake + LOCAL)

    # install.sh: nothing copied when a file of the tree has a syntax error
    for broken, bad in (('src/opnsense/mvc/app/library/OPNsense/Quota/Aliases.php', lambda t: t.replace('class Aliases', 'class Aliases {', 1)),
                        ('src/opnsense/scripts/quota/account.py', lambda t: t + '\ndef broken(:\n')):
        path = os.path.join(box.repo, broken)
        kept = open(path, encoding='utf-8').read()
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(bad(kept))
        rc, out = box.run('install/install.sh')
        check('install.sh, %s with a syntax error: stopped, nothing copied, nothing asked' % os.path.basename(broken),
              (rc != 0, box.plugin_files(), box.called()), (True, [], []))
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(kept)

    # install.sh, a fresh install: off by default
    for cache in CACHES:
        box.write(box.fake + cache, 'cached')
    box.write(os.path.join(box.repo, '.source-commit'), COMMIT + ' 2026-11-20T12:00:00+00:00\n')
    box.forget()
    rc, out = box.run('install/install.sh')
    check('install.sh: done, where the page is, and that it is off', (rc, out.strip().splitlines()[-1:]),
          (0, ['Quotas installed: Firewall > Quotas (off until it is turned on in Settings)']))
    laid = [f for f in box.plugin_files() if f.startswith(LOCAL) and not f.startswith('/usr/local/share/') and f != MENU]
    check('install.sh: every file of src/ laid down, and nothing else', laid, source_files())
    check('install.sh: the menu file placed, the caches cleared', (box.read(MENU), [c for c in CACHES if os.path.exists(box.fake + c)]),
          (menu_own, []))
    check('install.sh, off: the table emptied, the alias, the filter, cron, the table taken out of pf',
          box.called('configctl') + box.called('service'), APPLY_OFF + ['service configd restart'])
    check('install.sh: the modes', [box.mode(p) for p in (
        '/usr/local/opnsense/scripts/quota/account.py', '/usr/local/opnsense/scripts/quota/aliases.php',
        '/usr/local/opnsense/scripts/quota/place-menu.sh', BOOT, HOOK, '/usr/local/etc/cron.d/quota',
        '/usr/local/opnsense/service/conf/actions.d/actions_quota.conf',
        '/usr/local/opnsense/scripts/quota/i18n/ui/source.json',
        '/usr/local/opnsense/scripts/quota/release-keys/xgs-release-key-13ed7f86.pub')],
        [0o755, 0o755, 0o755, 0o755, 0o644, 0o644, 0o644, 0o644, 0o644])
    check('install.sh: the state directory, 0750', box.mode(STATE), 0o750)
    check('install.sh: the commit recorded for the self-update',
          '"commit": "%s"' % COMMIT in (box.read('/usr/local/share/os-quota/installed.json') or ''), True)

    # install.sh again: on, os-xgs-npu there
    box.config(ON)
    box.write(box.fake + XGS, '<menu/>')
    box.forget()
    rc, out = box.run('install/install.sh')
    check('install.sh, on: XGS > Quotas, counting', (rc, out.strip().splitlines()[-1:]),
          (0, ['Quotas installed: XGS > Quotas (counting)']))
    check('install.sh, on: the alias, the filter, cron, then one read', box.called('configctl'), APPLY_ON)

    # the boot's hook, as installed
    box.write(box.fake + '/usr/local/opnsense/scripts/quota/account.py',
              '#!/bin/sh\necho "account.py $*" >> %s\nexit 3\n' % box.calls, 0o755)
    box.forget()
    rc, out = box.sh(box.fake + BOOT)
    check('the boot\'s hook: one read, and 0 whatever it answered', (rc, box.called('account.py')), (0, ['account.py ']))

    # uninstall.sh: the table and the alias first, then the files
    os.remove(box.fake + XGS)
    box.write(box.fake + STATE + '/state.json', '{}')
    os.makedirs(box.fake + '/usr/local/opnsense/scripts/quota/__pycache__', exist_ok=True)
    box.write(box.tables, '-pa----\tquota_over\n-pa----\tbogons\n')
    box.forget()
    rc, out = box.run('install/uninstall.sh')
    calls = box.called()
    check('uninstall.sh: a read in progress ended, the table emptied and the alias taken out while the hook is there, first',
          calls[:3], ['pkill -f %s/usr/local/opnsense/scripts/[q]uota/' % box.fake, 'configctl quota flush hook=yes',
                      'configctl quota remove hook=yes'])
    check('uninstall.sh: nothing of the plugin left - files, state', box.plugin_files(), [])
    check('uninstall.sh: then configd, the filter and cron, without the hook',
          [c for c in calls if c.startswith(('service', 'configctl filter', 'configctl cron'))],
          ['service configd restart', 'configctl filter reload skip_alias hook=no', 'configctl cron restart hook=no'])
    check('uninstall.sh: the table taken out of pf, its alias gone; pf\'s own left', box.called('pfctl -t'),
          ['pfctl -t quota_over -T kill'])
    check('uninstall.sh: said', (rc, out.strip().splitlines()[-1]), (0, 'Quotas removed; its settings stay in config.xml'))
    box.config(ON.replace('</OPNsense>', '<Firewall><Alias><aliases><alias><name>quota_over</name></alias></aliases></Alias>'
                                         '</Firewall></OPNsense>'))
    box.forget()
    rc, out = box.run('install/uninstall.sh')
    check('uninstall.sh with the alias still in Firewall: Aliases (a rule names it): its table left to OPNsense',
          (rc, box.called('pfctl -t')), (0, []))
    box.write(box.tables, '-pa-r--\tquota_over\n')
    box.config(OFF)
    box.forget()
    rc, out = box.run('install/uninstall.sh')
    check('uninstall.sh, a rule still using the table: left', box.called('pfctl -t'), [])
    # the boot's hook left behind by something else, its script gone: nothing, 0
    shutil.copy(os.path.join(box.repo, 'src/etc/rc.syshook.d/start/70-quota'), os.path.join(tmp, '70-quota'))
    box.forget()
    rc, out = box.sh(os.path.join(tmp, '70-quota'))
    check('the boot\'s hook with account.py gone: nothing done, 0', (rc, box.called()), (0, []))

    # the package: pkg lays down the files of src/; post-install does the Apply; the old package's
    # pre-deinstall does nothing in an upgrade; a removal: the table and the alias, then post-deinstall
    shutil.copytree(os.path.join(box.repo, 'src'), box.fake + LOCAL, dirs_exist_ok=True)
    for path in source_files():
        os.chmod(box.fake + path, 0o755 if open(box.fake + path, 'rb').read(2) == b'#!' else 0o644)
    box.write(box.fake + '/usr/local/sbin/configctl', '#!/bin/sh\nexec configctl "$@"\n', 0o755)
    box.write(box.fake + '/usr/local/etc/rc.d/configd', '#!/bin/sh\nservice configd "$@"\n', 0o755)
    box.python3()
    box.config(OFF)
    box.forget()
    rc, out = box.run('pkg/post-install.sh')
    check('post-install.sh: the menu placed, said, off', (rc, box.read(MENU) == menu_own, out.strip().splitlines()[-1]),
          (0, True, 'Quotas installed: the page is at Firewall > Quotas (off until it is turned on in Settings)'))
    check('post-install.sh, off: configd, then the Apply in its order', box.called('service') + box.called('configctl'),
          ['service configd restart'] + APPLY_OFF)
    check('post-install.sh: the state directory', box.mode(STATE), 0o750)
    box.config(ON)
    box.forget()
    rc, out = box.run('pkg/post-install.sh')
    check('post-install.sh, on (an upgrade): the alias, the filter, cron and a read on the new code',
          box.called('configctl'), APPLY_ON)
    box.forget()
    rc, out = box.run('pkg/pre-deinstall.sh', env={'PKG_UPGRADE': 'true'})
    check('pre-deinstall.sh in an upgrade: nothing done', (rc, box.called()), (0, []))
    rc, out = box.run('pkg/pre-deinstall.sh', env={'PKG_UPGRADE': ''})
    check('pre-deinstall.sh in a removal: a read in progress ended, the table emptied, the alias taken out',
          box.called(), ['pkill -f %s/usr/local/opnsense/scripts/[q]uota/' % box.fake, 'configctl quota flush hook=yes',
                         'configctl quota remove hook=yes'])
    os.makedirs(box.fake + '/usr/local/opnsense/scripts/quota/__pycache__', exist_ok=True)
    box.write(box.fake + '/usr/local/opnsense/scripts/quota/__pycache__/account.cpython-311.pyc', 'x')
    for path in source_files():
        os.remove(box.fake + path)
    box.write(box.fake + STATE + '/state.json', '{}')
    box.write(box.tables, '-pa----\tquota_over\n')
    box.config(OFF)
    box.forget()
    rc, out = box.run('pkg/post-deinstall.sh')
    check('post-deinstall.sh: nothing of the plugin left - the menu file, Python\'s caches, the state', box.plugin_files(), [])
    check('post-deinstall.sh: configd, the filter and cron, the table taken out of pf',
          box.called('service') + box.called('configctl') + box.called('pfctl -t'),
          ['service configd restart', 'configctl filter reload skip_alias hook=no', 'configctl cron restart hook=no',
           'pfctl -t quota_over -T kill'])

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
