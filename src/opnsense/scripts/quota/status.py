#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""What the page shows, as one JSON object: whether the plugin is on, each quota with what its host used
this cycle, the last read and the last error, the table and how many addresses pf holds in it, and what
the plugin depends on - its alias, os-xgs-npu's cut list, and whether the hardware's counts reach pf.

    status.py        the cards and the Quotas tab

Read only; it prints JSON and exits 0 whatever it could not read.
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import account                                                           # noqa: E402
import enforce                                                           # noqa: E402
import settings                                                          # noqa: E402


def row(q, qs):
    """One quota as the Quotas tab shows it."""
    qs = qs if isinstance(qs, dict) else {}
    on = q['enabled'] and qs.get('since') is not None
    used = int(qs.get('up', 0)) + int(qs.get('down', 0))
    shares = []
    if q['volume']:
        shares.append(used / q['volume'])
    if q['minutes']:
        shares.append(int(qs.get('minutes', 0)) / q['minutes'])
    share = max(shares) if shares else 0.0
    over = bool(qs.get('over')) and q['enabled']
    if not q['enabled']:
        state = 'off'
    elif q['host'] is None:
        state = 'unreadable'
    elif qs.get('own'):
        state = 'own'
    elif over:
        state = 'over'
    elif not on:
        state = 'waiting'
    elif share >= account.NEAR:
        state = 'near'
    else:
        state = 'under'
    return {
        'uuid': q['uuid'], 'enabled': q['enabled'], 'host': q['host_text'],
        'kind': q['host'][0] if q['host'] else None, 'addresses': list(qs.get('addresses') or []),
        'description': q['description'], 'cycle': q['cycle'],
        'start': qs.get('start'), 'end': qs.get('end'),
        'volume': q['volume'], 'minutes_limit': q['minutes'],
        'up': int(qs.get('up', 0)), 'down': int(qs.get('down', 0)), 'used': used,
        'minutes': int(qs.get('minutes', 0)), 'percent': round(share * 100, 1),
        'over': over, 'over_at': qs.get('over_at') if over else None, 'why': list(qs.get('why') or []) if over else [],
        'state': state, 'reset_at': qs.get('reset_at'),
    }


def report(config=None, path=account.STATE, pf=None, project=account.PROJECT):
    conf = settings.read(config)
    alias = settings.alias(config)
    state = account.load(path)
    pf = pf or enforce.Pf()
    held = pf.show() if conf['enabled'] else None
    quotas = state.get('quotas') if isinstance(state.get('quotas'), dict) else {}
    rows = [row(q, quotas.get(q['uuid'])) for q in conf['quotas']]
    listed = bool(alias and alias['uuid'] and alias['uuid'] in conf['cut_lists'])
    # whether the plugin put its alias in the cut list itself (aliases.php's record): recorded and not
    # listed, the owner took it out; neither, it has not been put there yet
    recorded = bool(alias and alias['uuid'] and alias['uuid'] in conf['cut_added'])
    return {
        'enabled': conf['enabled'], 'read': conf['read'], 'project': os.path.isdir(project), 'xgs': conf['xgs'],
        'count_to_pf': conf['count_to_pf'], 'cut_in_hardware': conf['cut_in_hardware'], 'cut_listed': listed,
        'cut_recorded': recorded,
        'alias': None if alias is None else {'ours': alias['ours'], 'enabled': alias['enabled'],
                                             'external': alias['type'] == 'external'},
        'table': None if held is None else len(held),
        'role': state.get('role'), 'last': state.get('last'), 'error': state.get('error'),
        'minute_bytes': conf['minute_bytes'], 'near_percent': int(account.NEAR * 100),
        'quotas': rows,
        'counts': {
            'quotas': sum(1 for r in rows if r['enabled']),
            'over': sum(1 for r in rows if r['state'] == 'over'),
            'near': sum(1 for r in rows if r['state'] == 'near'),
            'used': sum(r['used'] for r in rows if r['enabled']),
        },
    }


def main(argv):
    try:
        print(json.dumps(report(), sort_keys=True))
    except Exception as error:          # the page says it could not be read, never a crash
        print(json.dumps({'error': {'at': int(time.time()), 'message': str(error)}}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
