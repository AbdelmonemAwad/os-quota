#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""A quota's cycle: when the one a moment falls in began, and when the next begins, in the firewall's
own time zone (System: Settings: General).

    day      from 00:00
    week     from Monday 00:00
    month    from the 1st, 00:00

The start of each is found through the calendar - mktime with the summer-time flag left to the zone -
so a day is 23 or 25 hours long where the clocks change, as the owner's clock is. A start day of the
owner's choosing is phase 2's (the plan's top-09).
"""

import datetime
import time

KINDS = ('day', 'week', 'month')


def _midnight(day):
    """The time a calendar day begins, local time."""
    return int(time.mktime((day.year, day.month, day.day, 0, 0, 0, 0, 0, -1)))


def start(kind, now):
    """When the cycle of this kind that now falls in began."""
    t = time.localtime(now)
    today = datetime.date(t.tm_year, t.tm_mon, t.tm_mday)
    if kind == 'week':
        today -= datetime.timedelta(days=today.weekday())
    elif kind == 'month':
        today = today.replace(day=1)
    begin = _midnight(today)
    # A zone whose clocks change at midnight has no 00:00 that day: mktime gives the hour after, and a
    # moment before it still belongs to the day before.
    if begin > now:
        return start(kind, begin - 1)
    return begin


def end(kind, begin):
    """When the cycle that began at begin ends: the next one's start."""
    t = time.localtime(begin)
    day = datetime.date(t.tm_year, t.tm_mon, t.tm_mday)
    if kind == 'week':
        day += datetime.timedelta(days=7)
    elif kind == 'month':
        day = (day.replace(day=28) + datetime.timedelta(days=4)).replace(day=1)
    else:
        day += datetime.timedelta(days=1)
    return _midnight(day)


def current(kind, now):
    """(start, end) of the cycle now falls in."""
    begin = start(kind, now)
    return begin, end(kind, begin)
