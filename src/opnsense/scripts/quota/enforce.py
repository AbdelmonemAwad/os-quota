#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""The block: the table quota_over made to hold the addresses of the hosts over their quota, and the cut
of the connections such a host already has open.

The table is the External alias aliases.php writes in Firewall: Aliases; plugins.inc.d/quota.inc blocks
what comes in from it and what comes in for it, before the owner's rules, all but DNS and the web GUI on
the firewall itself (settled point 7's starred choice), which it leaves to the anti-lockout rule and the
owner's own rules, as they were before the host went over. It is made from the counts each time, never
only edited: an address that should not be there goes, one missing is added, so a restart, a boot - pf's
tables live in the kernel - or a table emptied by hand is put right at the next minute's run.

A block stops new connections only. The ones already open are cut (settled point 6) by the read that
blocks the host, at once - what the table has just gained, and on the first read after a pause every host
it holds (account.cut_here()):

  - on the coprocessor first, where os-xgs-npu is installed: its hwdrop.drop_addresses(), which with XGS:
    Settings' "Cut in hardware" on drops every connection with an end among those addresses there at once,
    both ways, and with it off drops none (drop_in_hardware(), below);
  - then every pf state with an end among them, killed by its id as OPNsense's own Sessions page kills one
    (pfctl -k id -k id/creator). The states are read again after the table has the address, so one opened
    in between is not missed. A connection the coprocessor forwards goes with its state: each driver takes
    it out of hardware once pf no longer holds it.

Where os-xgs-npu is installed, aliases.php puts quota_over in its XGS: Settings, "Cut open connections when
listed", too: lists_cut.py compares the table with its last minute's and cuts what it gained - by then
nothing, or what came in between. Until 2026-11-20 the cut was left to it there wherever it would take an
address as new, and its minute was the cost: in the lab the cut came 60 s after the block, and the second
XGS 3300 at 3 Gbit/s let 31.5 GB pass after the limit, the XGS 136 9.5 GB. Where the owner took quota_over
out of that list after the plugin put it there, nothing is cut, here either: his choice stands.

THE HARDWARE STEP comes from os-blocklists' cut.py (2026-11-16, its deadline 2026-11-17): os-xgs-npu's
hwdrop.py loaded from its installed place, not copied; HW_DEADLINE seconds for it, in a thread of its own,
and then the pf cut goes on whatever it is doing (within()), its count "unknown". It needs root, as cron,
configd and the boot run the read.

Leaving the table cuts nothing: a host whose cycle starts again just passes again. A connection the
coprocessor dropped - here or by lists_cut.py - stays dropped there while its sender goes on sending it,
whatever the table says after, so where os-xgs-npu is installed the read that takes an address out of the
table hands its connections back to the host (release_in_hardware(), hwdrop.release_addresses(), as
os-blocklists' cut.py hands back the entries a list lost), and pf decides their frames again: a sender that
kept sending all along gets through again. Its step has the same HW_DEADLINE and thread as the drop and
stops no read; one left at its deadline or failed is tried again at the next read (account.hand_back()).
At the plugin's removal it is done once, for all the table held and all that was kept, as no read
follows: one left at its deadline or failed then leaves those connections dropped on the coprocessor until
their senders stop, and the log says so, and what frees them.
"""

import importlib.util
import ipaddress
import os
import subprocess
import sys
import threading

import states

PFCTL = '/sbin/pfctl'
TABLE = 'quota_over'
BATCH = 64
HW_DEADLINE = 5             # seconds the hardware step may take; then the pf cut goes on without it
UNKNOWN = 'unknown'         # how many a hardware step dropped, when it was left at its deadline or failed
_left = []                  # the hardware steps left at their deadline, while they still run


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


def hwdrop(path, say):
    """os-xgs-npu's hwdrop module, loaded from its installed place (path) and not copied; None when it is
    not there or does not load. Loaded only when a read has something to cut, after everything this plugin
    imports: hwdrop puts its own folder first on the module search path to import its flows.py, where a
    later `import status` would find os-xgs-npu's status.py - the path is put back as it was once it has
    loaded."""
    if not path or not os.path.isfile(path):
        return None
    saved = list(sys.path)
    try:
        spec = importlib.util.spec_from_file_location('xgs_hwdrop', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception as error:
        say('os-xgs-npu\'s hwdrop.py could not be loaded, nothing dropped in hardware: %s' % error)
        return None
    finally:
        sys.path[:] = saved


class HardwareLate(Exception):
    """The hardware step's time is up: raised to within()'s caller at the deadline, and in the step itself
    at its next `in` test (Until), which ends it there."""


class HardwareBusy(HardwareLate):
    """A hardware step left at its deadline still runs: no second one is started beside it."""


class Until:
    """A collection whose `in` test is `inner`'s until `stop` is set, and raises HardwareLate after.
    os-xgs-npu's hwdrop asks it once for each end of each connection of the flow table, between two calls
    of the driver, and lets HardwareLate through: a step left at its deadline writes no verdict after it
    and ends at its next connection - hwdrop's paging generator closed on the way out, whose `finally`
    puts the page place it shares with the other readers back to 0 and lets the flow-table lock go."""

    def __init__(self, inner, stop):
        self.inner, self.stop = inner, stop

    def __contains__(self, item):
        if self.stop.is_set():
            raise HardwareLate()
        return item in self.inner

    def __iter__(self):
        return iter(self.inner)

    def __len__(self):
        return len(self.inner)


def within(seconds, what, *args):
    """what(stop, *args) in a thread of its own, waited for `seconds` and no longer: its result, or a
    RuntimeError with the text of what it raised; HardwareLate at the deadline, `stop` set for it. The
    thread is a daemon: left at its deadline it ends at its next Until test, at the end of the driver call
    it is in, or with the read's process, which it never holds up - and as long as it runs no other is
    started (HardwareBusy). With the process goes the flow-table lock it may hold, a lock of an open file.
    No signal and no timer: os-blocklists' first deadline, a real-time timer in the main thread, fired in
    hwdrop's paging and held the pf cut behind a sysctl."""
    _left[:] = [t for t in _left if t.is_alive()]
    if _left:
        raise HardwareBusy()
    stop = threading.Event()
    done = {}

    def step():
        try:
            done['value'] = what(stop, *args)
        except HardwareLate:
            pass                # stopped at its deadline: the caller has gone on
        except Exception as error:      # only its text: what it held is let go here, in this thread
            done['error'] = '%s: %s' % (type(error).__name__, error)

    worker = threading.Thread(target=step, name='quota-hwdrop', daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        stop.set()
        _left.append(worker)
        raise HardwareLate()
    if 'error' in done:
        raise RuntimeError(done['error'])
    return done.get('value')


def ends(addresses):
    """The addresses as hwdrop writes a connection's ends - str(ipaddress.ip_address(...)), IPv6 in its
    short form - and none that is not an address."""
    out = set()
    for a in addresses:
        try:
            out.add(str(ipaddress.ip_address(a)))
        except ValueError:
            continue
    return out


def drop_in_hardware(addresses, path, say=None):
    """Every connection with an end among addresses dropped on the coprocessor by os-xgs-npu's hwdrop at
    path, before their pf states are killed: how many it took DROP for - 0 with "Cut in hardware" off,
    which hwdrop asks itself; UNKNOWN when the step was left at its deadline or failed, as some may have
    been dropped by then; None without hwdrop.py, or one that does not load. One call, which reads the
    whole flow table. What it could not do is said through say(message)."""
    say = say or (lambda message: None)
    hw = hwdrop(path, say)
    if hw is None:
        return None
    match = ends(addresses)
    try:
        return int(within(HW_DEADLINE, lambda stop: hw.drop_addresses(Until(match, stop))) or 0)
    except HardwareBusy:
        say('the cut in hardware: a step left at its deadline still runs, none started beside it; how many '
            'were dropped is not known, the pf cut goes on')
    except HardwareLate:
        say('the cut in hardware took more than %d s: left there, how many were dropped is not known, the pf '
            'cut goes on' % HW_DEADLINE)
    except Exception as error:      # hwdrop says it never raises; a cut is not stopped by it if it does
        say('the cut in hardware failed, how many were dropped is not known, the pf cut goes on: %s' % error)
    return UNKNOWN


def named(addresses, most=5):
    """Addresses as a log line names them: the first `most`, and how many more."""
    addresses = list(addresses)
    more = len(addresses) - most
    return ', '.join(addresses[:most]) + (' and %d more' % more if more > 0 else '')


def release_in_hardware(addresses, path, say=None, later=True):
    """Every connection with an end among addresses - what quota_over has lost - handed back to the host by
    os-xgs-npu's hwdrop at path, as os-blocklists' cut.py hands back the entries a list lost: a connection
    the coprocessor dropped stays dropped there while its sender goes on sending, whatever the table says
    after (os-xgs-npu's REMAINING A15); handed back, pf decides its frames again. "Cut in hardware" is not
    asked: one dropped while it was on is handed back once it is off as well. How many the driver handed
    back; UNKNOWN when the step was left at its deadline or failed; None without hwdrop.py, one that does
    not load, or one older than its release_addresses, which hands nothing back by address.

    `later`: whether a read follows that tries the addresses again, as the caller keeps them. At the
    plugin's removal none does, and what say() is told then is what is true: the connections the step did
    not hand back stay dropped on the coprocessor until their senders stop, and XGS: Offloaded Flows'
    Return to host, or a reboot, frees them."""
    say = say or (lambda message: None)
    hw = hwdrop(path, say)
    if hw is None or not hasattr(hw, 'release_addresses'):
        return None
    match = ends(addresses)
    if later:
        what, then = 'the hand-back from hardware', 'tried again at the next read'
    else:
        what = 'the hand-back from hardware at the removal of Quotas'
        then = ('the connections of %s that the coprocessor dropped and it did not hand back stay dropped there until '
                'their senders stop - XGS: Offloaded Flows\' Return to host, or a reboot, frees them' % named(addresses))
    try:
        return int(within(HW_DEADLINE, lambda stop: hw.release_addresses(Until(match, stop))) or 0)
    except HardwareBusy:
        say('%s: a step left at its deadline still runs, none started beside it; %s' % (what, then))
    except HardwareLate:
        say('%s took more than %d s and was left there; %s' % (what, HW_DEADLINE, then))
    except Exception as error:      # hwdrop says it never raises; nothing here is stopped by it if it does
        say('%s failed (%s); %s' % (what, error, then))
    return UNKNOWN


def flush(pf):
    """The table emptied: the addresses it held, sorted, or None when there is no such table."""
    held = pf.show()
    if held is None:
        return None
    if held:
        pf.change('delete', sorted(held))
    return sorted(held)


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
