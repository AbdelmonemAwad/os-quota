#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""The page (src/opnsense/mvc/app/views/OPNsense/Quota/index.volt): its script run under node, with each
lang._() given its English as Volt gives it - escaped - and stand-ins for jQuery, OPNsense's UIBootgrid,
ajaxGet, ajaxCall, mapDataToFormUI, saveFormToEndpoint and BootstrapDialog; and its markup read for what
the script asks of it.

What is checked: the cards for a status that cannot be read, the plugin off, a host over and one near, the
last error, the fifth card when os-xgs-npu does not give pf the hardware's counts; the quiet lines each
shown when it should be, and what those of the cut say; the grid's formatters - the host and a MAC's addresses, the volume used of its
limit, the minutes, the cycle and its end, each state; the Reset command asking first, then calling the
API with the row's id; Apply from each tab; every formatter the grid's columns name defined, and every
element the script looks for by id on the page.

    python3 tools/test-page.py"""
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = os.path.join(ROOT, 'src', 'opnsense', 'mvc', 'app', 'views', 'OPNsense', 'Quota', 'index.volt')

failures = 0
checks = 0


def check(name, got, want):
    global failures, checks
    checks += 1
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


TEXT = open(PAGE, encoding='utf-8').read()


def volt(text):
    """Each {{ lang._('...') }} as Volt hands it to the page: the English, escaped."""
    def one(m):
        raw = m.group(1).replace("\\'", "'").replace('\\\\', '\\')
        return html.escape(raw, quote=True).replace('&#x27;', '&#039;')
    return re.sub(r"\{\{\s*lang\._\('((?:[^'\\]|\\.)*)'\)\s*\}\}", one, text)


SCRIPT = volt(TEXT.split('<script>', 1)[1].split('</script>', 1)[0])
MARKUP = TEXT.split('</script>', 1)[1]

STUBS = r'''
const ready = [], grids = {}, elements = {}, calls = [], dialogs = [];
let answers = {};
function decode(h) {
    return String(h).replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#039;/g, "'")
        .replace(/&amp;/g, '&');
}
function El(tag, cls) { this.tag = tag; this.cls = cls || ''; this.kids = []; this.txt = ''; this.shown = undefined;
    this.attrs = {}; this.dataset = {}; }
El.prototype.addClass = function (c) { this.cls = (this.cls + ' ' + c).trim(); return this; };
El.prototype.removeClass = function () { return this; };
El.prototype.append = function (e) { this.kids.push(e); return this; };
El.prototype.text = function (t) { if (t === undefined) { return this.txt; } this.txt = String(t); return this; };
El.prototype.html = function (h) { if (h === undefined) { return this.txt; } this.txt = this.tag === 'textarea' ? decode(h) : String(h); return this; };
El.prototype.empty = function () { this.kids = []; return this; };
El.prototype.toggle = function (b) { this.shown = !!b; return this; };
El.prototype.show = function () { this.shown = true; return this; };
El.prototype.attr = function (k, v) { if (v === undefined) { return this.attrs[k]; } this.attrs[k] = v; return this; };
El.prototype.prop = function () { return this; };
El.prototype.click = function (fn) { this.onclick = fn; return this; };
El.prototype.on = function () { return this; };
El.prototype.tab = function () { return this; };
El.prototype.data = function (k) { return this.dataset[k]; };
El.prototype.UIBootgrid = function (o) { grids[this.id] = o; return this; };
El.prototype.bootgrid = function (what) { calls.push('reload ' + this.id); return this; };
El.prototype.selectpicker = function () { return this; };
function $(arg) {
    if (typeof arg === 'function') { ready.push(arg); return undefined; }
    if (arg === document) { return { ready: function (fn) { ready.push(fn); } }; }
    if (arg instanceof El) { return arg; }
    if (typeof arg === 'string' && arg[0] === '<') {
        const m = arg.match(/^<(\w+)(?:\s+class="([^"]*)")?\s*\/?>$/);
        return new El(m[1], m[2]);
    }
    if (typeof arg === 'string' && /^#[\w-]+$/.test(arg)) {
        const id = arg.slice(1);
        if (!elements[id]) { elements[id] = new El('div'); elements[id].id = id; }
        return elements[id];
    }
    return new El('other');
}
$.each = function (o, fn) { if (Array.isArray(o)) { o.forEach(function (v, i) { fn(i, v); }); } else { Object.keys(o).forEach(function (k) { fn(k, o[k]); }); } };
$.map = function (a, fn) { return a.map(fn); };
const document = {}, window = { location: { hash: '' } }, history = { pushState: function () {} };
function ajaxGet(url, data, cb) { calls.push('GET ' + url); cb(answers[url]); }
function ajaxCall(url, data, cb) { calls.push('POST ' + url); cb(answers[url] || { status: 'ok' }); }
function saveFormToEndpoint(url, form, cb) { calls.push('SAVE ' + url + ' ' + form); cb(); }
function mapDataToFormUI(map) { calls.push('MAP ' + Object.values(map).join(' ')); return { done: function (fn) { fn(); } }; }
const BootstrapDialog = { TYPE_WARNING: 'warning', confirm: function (o) { dialogs.push(o.title); o.callback(true); } };
function cards() {
    return ((elements['qt-cards'] || { kids: [] }).kids).map(function (c) {
        return [c.cls.replace('xgs-card', '').trim(), c.kids[1].txt, c.kids[2].txt, c.kids[3].txt];
    });
}
function quiet() {
    const out = {};
    ['qt-off', 'qt-project', 'qt-project-pf', 'qt-alone', 'qt-backup', 'qt-unlisted', 'qt-unlisted-new', 'qt-noalias',
     'qt-notours'].forEach(function (id) {
        out[id] = elements[id] ? elements[id].shown : null;
    });
    return out;
}
'''

SCENARIO = r'''
const out = {};
const STATUS = '/api/quota/service/status';
answers[STATUS] = undefined;
ready.forEach(function (fn) { fn(); });
out.unreadable = cards();
const g = grids['grid-quotas'];
out.grid = { search: g.search, get: g.get, set: g.set, add: g.add, del: g.del, toggle: g.toggle,
             formatters: Object.keys(g.options.formatters).sort(), commands: Object.keys(g.commands) };

const base = { enabled: true, project: false, count_to_pf: null, cut_listed: false, role: 'master', near_percent: 80,
    alias: { ours: true, enabled: true, external: true }, last: { at: 1763640000, connections: 12 }, error: null,
    counts: { quotas: 3, over: 1, near: 1, used: 5300000000 },
    quotas: [
        { uuid: 'u1', kind: 'address', addresses: ['192.0.2.10'], used: 5200000000, minutes: 0, end: 1763683200, state: 'over',
          why: ['volume'], over_at: 1763640000, percent: 104 },
        { uuid: 'u2', kind: 'mac', addresses: ['192.0.2.11', '2001:db8:1::11'], used: 100000000, minutes: 85, end: 1763683200,
          state: 'near', why: [], percent: 85 },
        { uuid: 'u3', kind: 'mac', addresses: [], used: 0, minutes: 0, end: 1763683200, state: 'under', why: [], percent: 0 }] };
function show(status) { answers[STATUS] = status; elements['refreshAct'].onclick(); return { cards: cards(), quiet: quiet() }; }
out.on = show(base);
out.off = show(Object.assign({}, base, { enabled: false, counts: { quotas: 0, over: 0, near: 0, used: 0 } }));
out.error = show(Object.assign({}, base, { error: { at: 1763640000, message: 'pf states could not be read' } }));
out.hardware = show(Object.assign({}, base, { project: true, count_to_pf: false, cut_listed: true }));
out.pfonly = show(Object.assign({}, base, { project: true, count_to_pf: true, cut_listed: true, cut_in_hardware: false }));
out.unlisted = show(Object.assign({}, base, { project: true, count_to_pf: true, cut_recorded: true }));
out.unlisted_new = show(Object.assign({}, base, { project: true, count_to_pf: true, cut_recorded: false }));
out.backup = show(Object.assign({}, base, { role: 'backup' }));
out.noalias = show(Object.assign({}, base, { alias: null }));
out.notours = show(Object.assign({}, base, { alias: { ours: false, enabled: true, external: false } }));

show(base);
const f = g.options.formatters;
out.cells = {
    host_addr: f.host({}, { uuid: 'u1', host: '192.0.2.10' }),
    host_mac: f.host({}, { uuid: 'u2', host: '02:00:00:aa:bb:cc' }),
    host_none: f.host({}, { uuid: 'u3', host: '02:00:00:dd:ee:ff' }),
    volume: f.volume({}, { uuid: 'u1', volume: '5000' }),
    volume_none: f.volume({}, { uuid: 'u2', volume: '' }),
    volume_unknown: f.volume({}, { uuid: 'zz', volume: '1500' }),
    minutes: f.minutes({}, { uuid: 'u2', minutes: '100' }),
    minutes_none: f.minutes({}, { uuid: 'u1', minutes: '' }),
    cycle: f.cycle({}, { uuid: 'u1', cycle: 'Daily, from 00:00' }).replace(/until .*<\/span>/, 'until …</span>'),
    over: f.state({}, { uuid: 'u1' }).replace(/since <\/span>|since .*<\/span>/, 'since …</span>'),
    near: f.state({}, { uuid: 'u2' }),
    under: f.state({}, { uuid: 'u3' }),
    missing: f.state({}, { uuid: 'zz' })
};
calls.length = 0;
const button = new El('button');
button.dataset['row-id'] = 'u1';
g.commands.reset.method.call(button);
out.reset = { dialogs: dialogs.slice(), calls: calls.slice() };
calls.length = 0;
elements['applyQuotasAct'].onclick.call(elements['applyQuotasAct']);
out.apply_quotas = calls.slice();
calls.length = 0;
elements['applyAct'].onclick.call(elements['applyAct']);
out.apply_settings = calls.slice();
console.log(JSON.stringify(out));
'''

node = shutil.which('node')
if node is None:
    print('FAIL node is not installed, so the page\'s script cannot be run')
    sys.exit(1)

with tempfile.TemporaryDirectory() as tmp:
    path = os.path.join(tmp, 'page.js')
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write(STUBS + SCRIPT + SCENARIO)
    done = subprocess.run([node, path], capture_output=True, text=True, encoding='utf-8')
if done.returncode != 0:
    print('FAIL the page\'s script did not run: ' + (done.stderr or done.stdout).strip()[:800])
    sys.exit(1)
out = json.loads(done.stdout.strip().splitlines()[-1])

check('a status that cannot be read: one card that says so', out['unreadable'],
      [['bad', 'Quotas', 'Status could not be read.', ' ']])
check('the grid: on the settings API, every formatter its columns need, and Reset', out['grid'],
      {'search': '/api/quota/settings/search_quotas', 'get': '/api/quota/settings/get_quota/',
       'set': '/api/quota/settings/set_quota/', 'add': '/api/quota/settings/add_quota/', 'del': '/api/quota/settings/del_quota/',
       'toggle': '/api/quota/settings/toggle_quota/', 'formatters': ['cycle', 'host', 'minutes', 'state', 'volume'],
       'commands': ['reset']})
check('on: four cards - one over, one near, 5.3 GB counted, no error',
      [c[:3] for c in out['on']['cards']],
      [['bad', 'Over quota', '1'], ['warn', 'Near the limit', '1'], ['', 'Counted this cycle', '5.3 GB'], ['', 'Last error', 'none']])
check('on: what the cards say under their figures', [out['on']['cards'][0][3], out['on']['cards'][1][3],
                                                    out['on']['cards'][2][3].split(' · ')[1]],
      ['blocked until their cycle starts again', '80 % or more of a quota', '12 connections'])
check('on, without os-xgs-npu: the line that says the cut is done here, alone',
      out['on']['quiet'], {'qt-off': False, 'qt-project': False, 'qt-project-pf': False, 'qt-alone': True, 'qt-backup': False,
                           'qt-unlisted': False, 'qt-unlisted-new': False, 'qt-noalias': False, 'qt-notours': False})
check('off: grey cards, the line that says it', ([c[0] for c in out['off']['cards']], out['off']['cards'][0][2],
                                                 out['off']['quiet']['qt-off'], out['off']['quiet']['qt-alone']),
      (['', '', '', ''], 'off', True, False))
check('the last error: its card, its message', out['error']['cards'][3][0::3], ['warn', 'pf states could not be read'])
check('os-xgs-npu not giving pf the hardware\'s counts: a fifth card, and the line for os-xgs-npu',
      (len(out['hardware']['cards']), out['hardware']['cards'][4][:3], out['hardware']['quiet']['qt-project'],
       out['hardware']['quiet']['qt-unlisted']), (5, ['bad', 'Hardware traffic', 'not counted'], True, False))
check('the hardware\'s counts given to pf: four cards', len(out['unlisted']['cards']), 4)
check('"Cut in hardware" off: the line for os-xgs-npu without "in hardware first"',
      (out['pfonly']['quiet']['qt-project'], out['pfonly']['quiet']['qt-project-pf']), (False, True))
check('quota_over taken out of the cut list by the owner: said, and not the line that says the read cuts',
      (out['unlisted']['quiet']['qt-unlisted'], out['unlisted']['quiet']['qt-unlisted-new'],
       out['unlisted']['quiet']['qt-project'], out['unlisted']['quiet']['qt-project-pf']), (True, False, False, False))
check('quota_over not yet in the cut list: Apply puts it there, and the read that blocks cuts all the same',
      (out['unlisted_new']['quiet']['qt-unlisted-new'], out['unlisted_new']['quiet']['qt-unlisted'],
       out['unlisted_new']['quiet']['qt-project']), (True, False, False))
check('a CARP backup: said', out['backup']['quiet']['qt-backup'], True)
check('no alias yet: said', (out['noalias']['quiet']['qt-noalias'], out['noalias']['quiet']['qt-notours']), (True, False))
check('the owner\'s alias of that name: said', (out['notours']['quiet']['qt-notours'], out['notours']['quiet']['qt-noalias']),
      (True, False))
c = out['cells']
check('the host: an address as it is; a MAC with its addresses; a MAC with none seen',
      [c['host_addr'], c['host_mac'], c['host_none']],
      ['<span dir="ltr">192.0.2.10</span>',
       '<span dir="ltr">02:00:00:aa:bb:cc</span> <span class="text-muted"><span dir="ltr">192.0.2.11, 2001:db8:1::11</span></span>',
       '<span dir="ltr">02:00:00:dd:ee:ff</span> <span class="text-muted">no address seen</span>'])
check('the volume: used of its limit and the share; none; the limit alone before a read',
      [c['volume'], c['volume_none'], c['volume_unknown']],
      ['5.2 GB / 5.0 GB <span class="text-muted">104 %</span>', '<span class="text-muted">-</span>', '1.5 GB'])
check('the minutes: used of the limit; none', [c['minutes'], c['minutes_none']],
      ['85 / 100 minutes', '<span class="text-muted">-</span>'])
check('the cycle and when it ends', c['cycle'], 'Daily, from 00:00 <span class="text-muted">until …</span>')
check('the state: over and why, since when; near and its share; under; a row the status does not hold',
      [c['over'], c['near'], c['under'], c['missing']],
      ['<span class="text-danger">over its quota (volume)</span> <span class="text-muted">since …</span>',
       '<span class="text-warning">near the limit</span> <span class="text-muted">85 %</span>',
       '<span class="text-muted">under the limit</span>', '<span class="text-muted">off</span>'])
check('Reset: asked first, then the API with the row\'s id, then the page read again',
      out['reset'], {'dialogs': ['Reset the count'], 'calls': ['POST /api/quota/service/reset/u1', 'GET /api/quota/service/status',
                                                                'reload grid-quotas']})
check('Apply on the Quotas tab: no form saved, the Apply, the page read again', out['apply_quotas'],
      ['POST /api/quota/service/reconfigure', 'GET /api/quota/service/status', 'reload grid-quotas'])
check('Apply on Settings: the form saved first', out['apply_settings'][:2],
      ['SAVE /api/quota/settings/set frm_general', 'POST /api/quota/service/reconfigure'])

# the markup and the script agree
named = set(re.findall(r'data-formatter="(\w+)"', MARKUP))
check('every formatter a column names is the grid\'s or OPNsense\'s own', sorted(named - set(out['grid']['formatters'])),
      ['commands', 'rowtoggle'])
# base_form's own: its Apply button by apply_btn_id, and the progress mark beside it
ids = (set(re.findall(r'\bid="([\w-]+)"', MARKUP)) | set(re.findall(r"'apply_btn_id': '([\w-]+)'", MARKUP)) |
       {'frm_general_progress'})
asked = set(re.findall(r"\$\('#([\w-]+)'\)", SCRIPT))
check('every element the script looks for by id is on the page, or base_form\'s',
      sorted(asked - ids), [])
# what the page says of the overshoot and the block is what README says: as measured (settled point 4), up to
# the read that blocks and cuts; DNS and the GUI left to the owner's rules
note = re.search(r"lang\._\('(Each host is counted(?:[^'\\]|\\.)*)'\)", MARKUP).group(1)
check('the note under the grid: the overshoot as measured, up to the read that blocks and cuts - no longer a '
      'second minute for XGS: Settings - DNS and the GUI left to the anti-lockout and the owner\'s rules, a Pass port '
      'forward outside the block',
      [part in note for part in ('not measured yet', 'measured, 11.3 GB past a 500 MB quota',
                                 'before the read that blocks it and cuts its open connections',
                                 'two minutes', 'stay as the anti-lockout rule and the owner', 'Pass filter rule')],
      [False, True, True, False, True, True])


# what each line says of the cut: at the read that blocks, in hardware first only where "Cut in hardware" is on;
# the owner's choice kept; no "within a minute" left on the page
def line(ident):
    return re.search(r'<span id="%s"[^>]*>\{\{ lang\._\(\'((?:[^\'\\]|\\.)*)\'\) \}\}</span>' % ident, MARKUP).group(1)


check('the lines of the cut: at the read that blocks it - in hardware first with "Cut in hardware" on, all the same '
      'while quota_over is not yet listed, never where the owner took it out - and no "within a minute" left',
      (line('qt-project').endswith('cut at the read that blocks it, in hardware first.'),
       line('qt-project-pf').endswith('cut at the read that blocks it.'),
       line('qt-unlisted-new').endswith('cut all the same, at the read that blocks it.'),
       line('qt-unlisted').endswith('keeps the connections it has open.'),
       line('qt-alone').endswith('cut at once.'), 'within a minute' in TEXT),
      (True, True, True, True, True, False))

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
