#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""The quotas' count, once a minute from cron (settled point 2: the plan's minute; what a minute misses
is measured, not guessed), and when the page's Apply or Reset asks.

Each read:

  1. which addresses each quota's host has now: the address itself, or a MAC's addresses as OPNsense's
     host discovery has them (hosts.py) - never one of the firewall's own;
  2. pf's states read once (states.py), one count per connection, only those of a watched address;
  3. what each connection moved since the last read added to each quota whose host is one of its ends -
     every byte, to and from the firewall itself too (settled point 8). A connection the last read did
     not see counts whole when it began since then; one older than that - there before the quota was, or
     before the plugin was turned on - counts from here on, never what it carried before;
  4. a minute of use (the time quota) is a minute of the clock in which the host moved more than the
     threshold Settings gives, both ways together - PROVISIONAL default, see settings.MINUTE_KB;
  5. a quota whose cycle has turned starts again from nothing: its host passes again;
  6. the addresses of every host over a quota put in the table, the others taken out (enforce.py), and
     the connections such a host has open cut: by XGS: Settings' cut list where os-xgs-npu is installed
     (settled point 6), here at once without it - and here too whenever os-xgs-npu's lists_cut.py would
     not take the address as newly listed (cut_here()).

Everything is kept in /var/db/os-quota/state.json after each read - the counts of the cycle, the last
read's per-connection counts - so a restart or a boot in the middle of a cycle loses no count and counts
nothing twice; a boot then fills the table again (rc.syshook.d/start/70-quota).

On a CARP backup nothing is counted or blocked: the master counts (settled point 15's starred choice).
Off, nothing is counted and the table is emptied; the cycle's counts are kept. The table is emptied only
when it is the plugin's: no alias of its name, or the plugin's own - an alias quota_over that is the
owner's holds his addresses, never touched here.

    account.py                    one read: count, then block (cron, the page's Apply)
    account.py --reset UUID|all   a quota's counts of this cycle back to nothing, then a read
    account.py --flush            the table emptied, when it is the plugin's, and the counting paused (the
                                  plugin off, its removal)
    account.py --gone             the table taken out of pf once its alias is gone (Apply, removal)

Each prints one JSON object and exits 0: it never fails its caller; what it could not do is in its answer,
in the page's Last error and in the system log.
"""

import fcntl
import ipaddress
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cycles                                                            # noqa: E402
import enforce                                                           # noqa: E402
import hosts                                                             # noqa: E402
import settings                                                          # noqa: E402
import states                                                            # noqa: E402

try:
    import syslog
except ImportError:                     # not on every system the tests run on
    syslog = None

STATE_DIR = '/var/db/os-quota'
STATE = STATE_DIR + '/state.json'
LOCK = STATE_DIR + '/account.lock'
PROJECT = '/usr/local/opnsense/scripts/xgs'
# os-xgs-npu's lists_cut.py keeps, for each table it watches, what the table held at its last run - one
# file a table, by its name (its snapshot_path()) - and cuts only the addresses that file does not hold
LISTS_RECORD = '/var/db/os-xgs-npu/lists/' + settings.ALIAS + '.json'
SLACK = 2               # seconds: pf prints a state's age in whole seconds
NEAR = 0.8              # the page's "near the limit": 80 % of a quota, as os-netreport's cap
WAIT = 50               # seconds a read waits for another one to end
CLOCK = 3600            # seconds: a kept cycle that begins further than this ahead of the clock was begun by a
                        # clock that ran ahead
UUID = re.compile(r'^[0-9a-fA-F-]{36}$')


def log(message, error=False):
    if syslog is None:
        return
    try:
        syslog.openlog('quota', 0, syslog.LOG_DAEMON)
        syslog.syslog(syslog.LOG_ERR if error else syslog.LOG_NOTICE, message)
    except OSError:
        pass


def load(path=STATE):
    try:
        with open(path, encoding='utf-8') as handle:
            found = json.load(handle)
    except (OSError, ValueError):
        return {}
    return found if isinstance(found, dict) else {}


def save(state, path=STATE):
    os.makedirs(os.path.dirname(path), mode=0o750, exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as handle:
        json.dump(state, handle, sort_keys=True)
    os.replace(tmp, path)


class Firewall:
    """What a read asks of the firewall beside pf: its interfaces, its neighbours, whether os-xgs-npu is
    there. Stand-ins replace it in the tests."""

    def __init__(self, project=PROJECT):
        self.project = os.path.isdir(project)

    def interfaces(self):
        return hosts.interfaces()

    def neighbours(self):
        return hosts.neighbours()


def name(q):
    """How the log names a quota: its description, or its host."""
    return q['description'] or q['host_text'] or q['uuid']


def ident(q):
    """What a quota's state is kept for: its host as read, so another host in the same row starts anew."""
    return '%s %s' % q['host'] if q['host'] else ''


def owned(alias):
    """Whether the pf table quota_over is this plugin's to empty: there is no alias of that name, or it is
    the plugin's own External one. One of that name that is the owner's - or the plugin's made another kind
    by hand - holds his addresses, and the plugin never touches them."""
    return alias is None or (alias['ours'] and alias['type'] == 'external')


def pause(state):
    """Counting stopped - the plugin off, this firewall a CARP backup: the last read's connections are
    forgotten, and each quota counts again from the read that finds it on, never what passed meanwhile.
    Nothing here blocks meanwhile either, so the read that finds it on looks at every host it blocks."""
    state['conns'] = {}
    state['at'] = None
    state['blocking'] = False
    for qs in (state.get('quotas') or {}).values():
        qs['since'] = None


def fresh(q, begin, finish, now):
    return {'host': ident(q), 'cycle': q['cycle'], 'start': begin, 'end': finish, 'since': now,
            'up': 0, 'down': 0, 'minutes': 0, 'minute': None, 'minute_bytes': 0, 'minute_counted': False,
            'over': False, 'over_at': None, 'why': [], 'addresses': [], 'own': False, 'reset_at': None,
            'last_cycle': None}


def zero(qs):
    qs.update(up=0, down=0, minutes=0, minute_bytes=0, minute_counted=False, over=False, over_at=None, why=[])


def quota_state(state, q, now):
    """The quota's kept state, made for a row new or given another host, and started again when its cycle
    has turned - only forward: a clock set back does not start a cycle again.

    A clock that ran ahead and has come back is the one case where a cycle goes back: when the cycle kept
    begins more than CLOCK ahead of the clock, and the clock is inside the cycle the kept one followed,
    that cycle goes on with its counts and what was counted since - so the turn the clock made early gives
    neither a cycle for free nor one that does not turn at its real end. A clock further behind - a
    real-time clock that lost its time, until NTP sets it - changes nothing: the cycle kept goes on."""
    begin, finish = cycles.current(q['cycle'], now)
    qs = state['quotas'].get(q['uuid'])
    if not isinstance(qs, dict) or qs.get('host') != ident(q):
        qs = state['quotas'][q['uuid']] = fresh(q, begin, finish, now)
    elif qs.get('cycle') != q['cycle'] or begin > (qs.get('start') or 0):
        if qs.get('over'):
            log('%s: a new cycle - passes again' % name(q))
        left = {'cycle': qs.get('cycle'), 'start': qs.get('start'), 'up': qs.get('up', 0),
                'down': qs.get('down', 0), 'minutes': qs.get('minutes', 0)}
        zero(qs)
        qs.update(cycle=q['cycle'], start=begin, end=finish, last_cycle=left)
    elif ((qs.get('start') or 0) - now > CLOCK and isinstance(qs.get('last_cycle'), dict) and
          qs['last_cycle'].get('cycle') == q['cycle'] and qs['last_cycle'].get('start') == begin):
        left = qs['last_cycle']
        log('%s: the clock is back in the cycle it had left early - that cycle goes on, with its counts' % name(q))
        qs.update(start=begin, up=qs.get('up', 0) + left.get('up', 0), down=qs.get('down', 0) + left.get('down', 0),
                  minutes=qs.get('minutes', 0) + left.get('minutes', 0), last_cycle=None)
    # on again - or a clock set back past it, which would otherwise stop the count until it came round
    if qs.get('since') is None or qs['since'] > now:
        qs['since'] = now
    qs['end'] = cycles.end(qs['cycle'], qs['start'])
    return qs


def moved(addresses, conns, before, after, now):
    """(up, down): what the host of these addresses moved since the last read - up from it, down to it. A
    connection the last read held counts what it gained since; one it did not hold counts whole when it
    began at or after `after`, and nothing yet when it began before."""
    up = down = 0
    for key, c in conns.items():
        ini = c['initiator'] in addresses
        if not ini and c['responder'] not in addresses:
            continue
        prev = before.get(key)
        if isinstance(prev, dict) and c['ids'] & set(prev.get('ids') or ()):
            d0, d1 = max(0, c['up'] - prev.get('up', 0)), max(0, c['down'] - prev.get('down', 0))
        elif now - c['age'] >= after - SLACK:
            d0, d1 = c['up'], c['down']
        else:
            continue
        if ini:
            up, down = up + d0, down + d1
        else:
            up, down = up + d1, down + d0
    return up, down


def snapshot(conns, before):
    """What the next read compares with: each connection's ids and counts. A connection that goes on keeps
    the larger of its counts each way, so a state of it that ends first is never counted again."""
    out = {}
    for key, c in conns.items():
        up, down = c['up'], c['down']
        prev = before.get(key)
        if isinstance(prev, dict) and c['ids'] & set(prev.get('ids') or ()):
            up, down = max(up, prev.get('up', 0)), max(down, prev.get('down', 0))
        out[key] = {'ids': sorted(c['ids']), 'up': up, 'down': down}
    return out


def minute(qs, nbytes, threshold, now):
    """The time quota: the bytes of this minute of the clock, and the minute counted once they pass the
    threshold. Two reads in one minute make one minute; a minute no read fell in counts with the next."""
    this = int(now // 60)
    if qs.get('minute') != this:
        qs.update(minute=this, minute_bytes=0, minute_counted=False)
    qs['minute_bytes'] += nbytes
    if not qs['minute_counted'] and qs['minute_bytes'] > threshold:
        qs['minutes'] += 1
        qs['minute_counted'] = True


def judge(q, qs):
    """Which of the quota's limits its host has reached: ['volume'], ['time'], both or none."""
    why = []
    if q['volume'] and qs['up'] + qs['down'] >= q['volume']:
        why.append('volume')
    if q['minutes'] and qs['minutes'] >= q['minutes']:
        why.append('time')
    return why


def note_error(state, message, now):
    """The page's Last error. Said in the system log when it is new, or an hour after it last was: a
    fault that stays is not written there every minute."""
    last = state.get('error') if isinstance(state.get('error'), dict) else {}
    logged = last.get('logged') or 0
    if last.get('message') != message or now - logged >= 3600:
        log(message, error=True)
        logged = int(now)
    state['error'] = {'at': int(now), 'message': message, 'logged': logged}


def cut_here(fresh, conf, alias, project, record=None):
    """Which of `fresh` - addresses the table has just gained, or holds on the first read after a pause -
    this read cuts itself.

    Without os-xgs-npu, all of them: nothing else would. With it, XGS: Settings' cut list does (settled
    point 6): lists_cut.py drops the coprocessor's flows first, then kills the states, at its next minute.
    But it cuts only what is new to it - an address its own record of the table's last run does not hold -
    so an address that was in the table then it never cuts: one put back after a boot (the record outlives
    it), after the plugin was turned off and on, on a CARP master come back, or after a Reset and a second
    overrun within its minute. Those are cut here, as is everything while the alias was never put in its
    list (os-xgs-npu installed since the last Apply). Where the owner took it out of the list, nothing is
    cut: his choice stands, and the page says so. A record that cannot be read leaves the cut here too: a
    connection cut twice costs nothing, one never cut costs the quota."""
    fresh = set(fresh)
    if not project or not fresh:
        return fresh
    if alias['uuid'] not in conf['cut_lists']:
        return set() if alias['uuid'] in conf['cut_added'] else fresh
    try:
        with open(record or LISTS_RECORD, encoding='utf-8') as handle:
            seen = json.load(handle)
    except (OSError, ValueError):
        return fresh
    if not isinstance(seen, list):
        return fresh
    held = set()
    for item in seen:
        try:
            held.add(ipaddress.ip_network(item, strict=False))
        except (TypeError, ValueError):
            continue
    return {a for a in fresh if ipaddress.ip_network(a) in held}


def tick(state, conf, alias, pf, fw, now):
    """One read, on the state kept (changed in place): what it found, as the JSON answer."""
    state.setdefault('quotas', {})
    for uuid in [u for u in state['quotas'] if u not in {q['uuid'] for q in conf['quotas']}]:
        del state['quotas'][uuid]
    answer = {'status': 'ok', 'at': int(now)}

    if not conf['enabled']:
        pause(state)
        state['role'] = None
        if state.get('over') and owned(alias):
            enforce.flush(pf)
        state['over'] = []
        answer['status'] = 'off'
        return answer

    mine, role, error = fw.interfaces()
    state['role'] = role
    if error:
        note_error(state, 'the firewall\'s own addresses could not be read (%s): nothing counted or changed this minute'
                   % error, now)
        answer['status'] = 'failed'
        return answer
    if role == 'backup':
        pause(state)
        answer['status'] = 'backup'
        return answer

    on = [q for q in conf['quotas'] if q['enabled']]
    for q in conf['quotas']:
        if not q['enabled'] and isinstance(state['quotas'].get(q['uuid']), dict):
            state['quotas'][q['uuid']].update(since=None, over=False, over_at=None, why=[])

    # 1. each host's addresses now
    macs = {q['host'][1] for q in on if q['host'] and q['host'][0] == 'mac'}
    table, where, note = ({}, None, None)
    if macs:
        table, where, note = fw.neighbours()
    resolved = hosts.addresses_of(macs, table, mine)
    wanted = {}
    for q in on:
        if not q['host']:
            wanted[q['uuid']] = set()
        elif q['host'][0] == 'mac':
            wanted[q['uuid']] = resolved.get(q['host'][1], set())
        else:
            wanted[q['uuid']] = {q['host'][1]} - mine
    watched = set().union(*wanted.values()) if wanted else set()

    # 2. pf's states, once - not at all when no host has an address to watch
    started = time.monotonic()
    conns = None if watched else {}
    if watched:
        text = pf.states()
        if text is None:
            note_error(state, 'pf\'s states could not be read: nothing counted this minute', now)
            answer['status'] = 'failed'
        else:
            conns, read = states.parse(text, watched)
            answer['states'] = read
            answer['connections'] = len(conns)
            state['last'] = {'at': int(now), 'states': read, 'connections': len(conns),
                             'took': round(time.monotonic() - started, 3), 'neighbours': where}

    # 3-5. the counts, the minutes, the cycles
    before = state.get('conns') or {}
    previous = state.get('at')
    if previous and previous > now:
        previous = None             # a clock set back: the last read's time says nothing of what is new
    over = set()
    for q in on:
        qs = quota_state(state, q, now)
        qs['addresses'] = sorted(wanted[q['uuid']])
        qs['own'] = bool(q['host'] and q['host'][0] == 'address' and q['host'][1] in mine)
        # the read that finds a quota new, or on again, only starts it: what came before it is not its own
        if conns is not None and qs['since'] < now:
            after = max(qs['since'], previous or qs['since'])
            up, down = moved(wanted[q['uuid']], conns, before, after, now)
            qs['up'] += up
            qs['down'] += down
            minute(qs, up + down, conf['minute_bytes'], now)
        why = judge(q, qs)
        if why and not qs['over']:
            qs['over_at'] = int(now)
            log('%s: over its %s quota - %d address(es) blocked until its cycle starts again' %
                (name(q), ' and '.join(why), len(wanted[q['uuid']])))
        qs['over'] = bool(why)
        qs['why'] = why
        if why:
            over |= wanted[q['uuid']]
        else:
            qs['over_at'] = None
    if conns is not None:
        state['conns'] = snapshot(conns, before)
        state['at'] = int(now)
    if note and macs:
        answer['neighbours'] = note
    over -= mine

    # 6. the block, and the cut where this plugin does it. state['over'] is what the plugin put in the table
    # - the addresses it empties when turned off - so only a table it wrote changes it; state['blocking'],
    # whether the last read's table and rules were in force.
    resumed = not state.get('blocking')
    state['blocking'] = False
    if alias is None:
        if over:
            note_error(state, 'the alias %s is not in Firewall: Aliases - Apply makes it: no host is blocked' % settings.ALIAS, now)
    elif not alias['ours']:
        state['over'] = []
        if over:
            note_error(state, 'an alias named %s that is not this plugin\'s is in Firewall: Aliases: no host is blocked'
                       % settings.ALIAS, now)
    elif not alias['enabled'] or alias['type'] != 'external':
        if over:
            note_error(state, 'the alias %s is switched off or no longer External: no host is blocked' % settings.ALIAS, now)
    else:
        known = len(pf.errors)
        result = enforce.sync(pf, over)
        added, removed = result if result else ([], [])
        answer['added'], answer['removed'] = len(added), len(removed)
        # what the table gained; and on the first read after a pause - the plugin on again, this firewall
        # master again - every host in it: what it opened while nothing here blocked it, or what pfsync
        # brought from the other firewall, is open still
        to_cut = cut_here(set(added) | (over if resumed else set()), conf, alias, fw.project)
        if to_cut:
            answer['cut'] = enforce.cut(pf, sorted(to_cut))
            if answer['cut']:
                log('%d open connection(s) of %d host address(es) over their quota cut' % (answer['cut'], len(to_cut)))
        state['blocking'] = True
        if len(pf.errors) > known:
            note_error(state, '; '.join(pf.errors[known:]), now)
            answer['status'] = 'failed'
        state['over'] = sorted(over)
    answer['over'] = len(over)
    return answer


def reset(state, which, conf):
    """The counts of this cycle back to nothing for one quota, or all: [uuids] reset."""
    done = []
    for q in conf['quotas']:
        if which not in ('all', q['uuid']):
            continue
        qs = state.setdefault('quotas', {}).get(q['uuid'])
        if isinstance(qs, dict):
            if qs.get('over'):
                log('%s: reset by hand - passes again' % name(q))
            zero(qs)
            # never undone: a clock come back does not give back the counts of the cycle it had left
            qs['last_cycle'] = None
            qs['reset_at'] = int(time.time())
        done.append(q['uuid'])
    return done


class Lock:
    """One read at a time: cron's, the page's and a reset's would otherwise count the same bytes twice."""

    def __init__(self, path=LOCK, wait=None):
        self.path = path
        self.wait = WAIT if wait is None else wait
        self.handle = None
        self.gone = False

    def __enter__(self):
        os.makedirs(os.path.dirname(self.path), mode=0o750, exist_ok=True)
        self.handle = open(self.path, 'a')
        give_up = time.monotonic() + self.wait
        while True:
            try:
                fcntl.flock(self.handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= give_up:
                    return False
                time.sleep(0.5)
        # The plugin's removal takes /var/db/os-quota away, lock and all: a read that waited for the lock
        # meanwhile holds a file that is no longer there, and must not make the directory again with its
        # counts in it.
        try:
            self.gone = not os.path.samestat(os.stat(self.path), os.fstat(self.handle.fileno()))
        except OSError:
            self.gone = True
        return not self.gone

    def __exit__(self, *args):
        self.handle.close()


def main(argv, pf=None, fw=None, config=None, path=STATE, lock=LOCK):
    pf = pf or enforce.Pf()
    one = Lock(lock)
    with one as held:
        if not held and one.gone:
            print(json.dumps({'status': 'removed', 'message': 'Quotas is being removed: nothing done'}))
            return 0
        if not held:
            print(json.dumps({'status': 'busy', 'message': 'another read was still running'}))
            return 0
        state = load(path)
        kept = json.dumps(state, sort_keys=True)
        now = time.time()
        if argv[1:2] == ['--flush']:
            pause(state)
            answer = {'status': 'ok', 'emptied': None}
            if not settings.read(config)['read']:
                answer['note'] = 'config.xml could not be read: the table is left as it is'
            elif not owned(settings.alias(config)):
                answer['note'] = 'an alias named %s that is not this plugin\'s holds the table: left as it is' % settings.ALIAS
                state['over'] = []
            else:
                answer['emptied'] = enforce.flush(pf)
                state['over'] = []
            save(state, path)
            answer['errors'] = pf.errors
            print(json.dumps(answer))
            return 0
        if argv[1:2] == ['--gone']:
            killed = False
            if settings.read(config)['read'] and settings.alias(config) is None:
                killed = enforce.kill_table(pf)
            print(json.dumps({'status': 'ok', 'killed': killed, 'errors': pf.errors}))
            return 0
        conf = settings.read(config)
        if not conf['read']:
            note_error(state, 'config.xml could not be read: nothing counted or changed', now)
            save(state, path)
            print(json.dumps({'status': 'failed', 'message': state['error']['message']}))
            return 0
        done = None
        if argv[1:2] == ['--reset']:
            which = argv[2] if len(argv) > 2 else ''
            if which != 'all' and not UUID.match(which):
                print(json.dumps({'status': 'failed', 'message': 'a quota\'s id, or all'}))
                return 0
            done = reset(state, which, conf)
        try:
            answer = tick(state, conf, settings.alias(config), pf, fw or Firewall(), now)
        except Exception as error:      # never fail the caller: cron or the page
            note_error(state, 'the read stopped: %s' % error, now)
            answer = {'status': 'failed', 'message': str(error)}
        if done is not None:
            answer['reset'] = done
        # written only when something changed: off, a minute's run changes nothing and writes nothing
        if json.dumps(state, sort_keys=True) != kept:
            save(state, path)
        print(json.dumps(answer, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
