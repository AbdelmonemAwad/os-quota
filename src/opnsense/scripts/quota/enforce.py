#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""The block: the table quota_over made to hold the addresses of the hosts over their quota, and the cut
of the connections such a host already has open.

The table is the External alias aliases.php writes in Firewall: Aliases; plugins.inc.d/quota.inc blocks
what comes in from it and what comes in for it, before the owner's rules, and lets it reach DNS and the
web GUI on the firewall itself (settled point 7's starred choice), so nobody is locked out of the page
that says why. It is made from the counts each time, never only edited: an address that should not be
there goes, one missing is added, so a restart, a boot - pf's tables live in the kernel - or a table
emptied by hand is put right at the next minute's run.

A block stops new connections only. The ones already open are cut (settled point 6):

  - where os-xgs-npu is installed, by its XGS: Settings, "Cut open connections when listed", which
    aliases.php puts quota_over in: lists_cut.py compares the table with its last minute's and kills
    every state of an address it gained, the coprocessor's flow dropped first where "Cut in hardware" is
    on - within a minute (34 and 60 s measured, os-xgs-npu's lists-cut-2026-10-19);
  - without os-xgs-npu, here and at once: every state of an address the table gained, either end, killed
    by its id as OPNsense's own Sessions page kills one (pfctl -k id -k id/creator). The states are read
    again after the table has the address, so one opened in between is not missed.

Leaving the table cuts nothing: a host whose cycle starts again just passes again.
"""

import subprocess

import states

PFCTL = '/sbin/pfctl'
TABLE = 'quota_over'
BATCH = 64


class Pf:
    """pfctl, for the plugin's table. run(args) -> (exit status, output); a stand-in in the tests."""

    def __init__(self, run=None, pfctl=PFCTL):
        self.pfctl = pfctl
        self.run = run or self._run
        self.errors = []

    def _run(self, args):
        try:
            done = subprocess.run([self.pfctl] + args, capture_output=True, text=True, errors='replace', timeout=120)
        except (OSError, subprocess.SubprocessError) as error:
            return 1, str(error)
        return done.returncode, (done.stdout or '') + (done.stderr or '')

    def show(self, table=TABLE):
        """What the table holds, or None when pf has no such table."""
        status, out = self.run(['-t', table, '-T', 'show'])
        if status != 0:
            return None
        return {line.strip() for line in out.splitlines() if line.strip() and not line.startswith('pfctl')}

    def change(self, verb, addresses, table=TABLE):
        """Add or delete addresses, BATCH a call; False when pfctl refused one of the calls."""
        ok = True
        for i in range(0, len(addresses), BATCH):
            status, out = self.run(['-t', table, '-T', verb] + addresses[i:i + BATCH])
            if status != 0:
                ok = False
                self.errors.append('pfctl -t %s -T %s: %s' % (table, verb, out.strip()[:200]))
        return ok

    def states(self):
        """pfctl -vvs state's text, or None when it could not be read."""
        status, out = self.run(['-vvs', 'state'])
        if status != 0:
            self.errors.append('pfctl -vvs state: %s' % out.strip()[:200])
            return None
        return out

    def kill(self, ident):
        status, _ = self.run(['-k', 'id', '-k', ident])
        return status == 0


def sync(pf, want):
    """The table made to hold want: (added, removed) - sorted lists - or None when pf holds no such table
    and nothing is wanted in it (the plugin off, the filter not reloaded since its alias went)."""
    held = pf.show()
    if held is None and not want:
        return None
    held = held or set()
    add = sorted(set(want) - held)
    remove = sorted(held - set(want))
    if add:
        pf.change('add', add)
    if remove:
        pf.change('delete', remove)
    return add, remove


def cut(pf, addresses):
    """Every state with an end among addresses killed: how many were."""
    if not addresses:
        return 0
    text = pf.states()
    if text is None:
        return 0
    killed = 0
    for ident in states.ids_with(text, set(addresses)):
        if pf.kill(ident):
            killed += 1
    return killed


def flush(pf):
    """The table emptied: how many addresses it held, or None when there is no such table."""
    held = pf.show()
    if held is None:
        return None
    if held:
        pf.change('delete', sorted(held))
    return len(held)


def kill_table(pf):
    """The table taken out of pf when its alias is gone and no rule uses it: a table outlives its alias
    and goes on holding its addresses (os-blocklists, 2026-10-29). True when it was killed."""
    status, out = pf.run(['-v', '-s', 'Tables'])
    if status != 0:
        return False
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == TABLE:
            if 'r' in parts[0]:
                return False
            status, text = pf.run(['-t', TABLE, '-T', 'kill'])
            if status != 0:
                pf.errors.append('pfctl -t %s -T kill: %s' % (TABLE, text.strip()[:200]))
            return status == 0
    return False
