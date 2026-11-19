{#
 # SPDX-License-Identifier: BSD-2-Clause
 # Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 #
 # Firewall: Quotas (XGS: Quotas when os-xgs-npu is installed) - a quota for each host by volume and by
 # minutes of use, counted from pf's states, what each host used this cycle, and the settings.
 #}

<style>
    /* KIT-CSS-BEGIN */
    .xgs-cards { display: flex; flex-wrap: wrap; gap: 12px; padding: 15px; }
    .xgs-cards.xgs-top { padding: 0 0 15px; }
    .xgs-card { flex: 1 1 200px; min-width: 190px; border: 1px solid rgba(128, 128, 128, 0.25);
                border-inline-start: 4px solid #9e9e9e; border-radius: 3px; padding: 10px 14px;
                background-color: rgba(128, 128, 128, 0.04); }
    .xgs-card.ok { border-inline-start-color: #5cb85c; }
    .xgs-card.warn { border-inline-start-color: #f0ad4e; }
    .xgs-card.bad { border-inline-start-color: #d9534f; }
    .xgs-card .k { font-size: 11px; text-transform: uppercase; letter-spacing: .04em; opacity: 0.6; }
    .xgs-card .v { font-size: 19px; font-weight: 600; line-height: 1.3; margin: 2px 0; }
    .xgs-card .s { font-size: 12px; opacity: 0.7; }
    .xgs-card .fa { opacity: 0.35; float: inline-end; font-size: 18px; margin-top: 2px; }
    .xgs-head { padding-top: 5px; padding-bottom: 5px; font-size: 16px; }
    /* KIT-CSS-END */
    /* A grid whose columns fill the width shows a one-pixel sideways bar when no vertical one takes
       the difference; wide screens never need to scroll it sideways. */
    @media (min-width: 768px) {
        #grid-quotas .tabulator-tableholder { overflow-x: hidden; }
    }
    .qt-note { padding: 0 15px 10px; }
    .qt-foot { padding: 0 15px 15px; }
    .qt-quiet > span { display: block; }
</style>

<script>
    $(document).ready(function () {
        /* KIT-JS-BEGIN */
        /* A string as OPNsense's API and Volt's lang._() hand it over - escaped - made plain for .text(). */
        function plain(value) {
            return $('<textarea/>').html(value === null || value === undefined ? '' : String(value)).text();
        }

        /* One card: cls '' (grey, no judgement), 'ok', 'warn' or 'bad'; icon a Font Awesome name. */
        function card(cls, icon, key, value, sub) {
            return $('<div class="xgs-card"/>').addClass(cls)
                .append($('<i class="fa"/>').addClass(icon))
                .append($('<div class="k"/>').text(plain(key)))
                .append($('<div class="v"/>').text(plain(value)))
                .append($('<div class="s"/>').text(plain(sub || ' ')));
        }

        /* Until the first reading: the same cards, their keys, and an ellipsis for every value. */
        function cards_wait(target, keys) {
            $(target).empty();
            $.each(keys, function (i, key) {
                $(target).append(card('', 'fa-ellipsis-h', key, '…', ''));
            });
        }

        /* The selected tab kept in the address, as on OPNsense's own tabbed pages. */
        function keep_tab() {
            if (window.location.hash !== '') {
                $('a[href="' + window.location.hash + '"]').tab('show');
            }
            $('.nav-tabs a').on('shown.bs.tab', function (e) {
                history.pushState(null, null, e.target.hash);
            });
        }
        /* KIT-JS-END */

        /* the last status read, and each quota's use of this cycle by its row's uuid */
        let status = null;
        let use = {};

        const states = {
            'over': "{{ lang._('over its quota') }}",
            'near': "{{ lang._('near the limit') }}",
            'under': "{{ lang._('under the limit') }}",
            'off': "{{ lang._('off') }}",
            'waiting': "{{ lang._('counted from the next read') }}",
            'own': "{{ lang._('an address of the firewall: never counted') }}",
            'unreadable': "{{ lang._('the host cannot be read') }}"
        };
        const reasons = {
            'volume': "{{ lang._('volume') }}",
            'time': "{{ lang._('time') }}"
        };

        function count(n) {
            return n === null || n === undefined || n === '' ? '-' : Number(n).toLocaleString();
        }

        function when(ts) {
            return ts ? new Date(ts * 1000).toLocaleString() : '-';
        }

        /* bytes as the quotas count them: 1 KB = 1,000 bytes, 1 MB = 1,000 KB, as the Volume field */
        function size(n) {
            const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
            let v = Number(n) || 0, i = 0;
            while (v >= 1000 && i < units.length - 1) {
                v /= 1000;
                i++;
            }
            return (i === 0 ? String(v) : v.toFixed(v >= 100 ? 0 : 1)) + ' ' + units[i];
        }

        function share(used, limit) {
            return limit ? Math.floor(used * 100 / limit) + ' %' : '';
        }

        /*
         * Four cards (the plan's): the hosts over a quota, those near one, what the quotas counted in their
         * cycles, and the last error. A fifth where os-xgs-npu is installed and does not give pf the
         * hardware's counts: then a connection in hardware is counted for its first packets only.
         */
        function draw(data) {
            status = data;
            use = {};
            $.each((data && data.quotas) || [], function (i, q) {
                use[q.uuid] = q;
            });
            const $cards = $('#qt-cards').empty();
            if (!data || !data.quotas) {
                $cards.append(card('bad', 'fa-hourglass-half', "{{ lang._('Quotas') }}", "{{ lang._('Status could not be read.') }}",
                    data && data.error ? data.error.message : ''));
                return;
            }
            const c = data.counts || {};
            const on = !!data.enabled;
            const last = data.last || {};
            $cards.append(card(!on ? '' : (c.over ? 'bad' : 'ok'), 'fa-ban', "{{ lang._('Over quota') }}",
                on ? count(c.over) : "{{ lang._('off') }}",
                on ? (c.over ? "{{ lang._('blocked until their cycle starts again') }}" :
                    count(c.quotas) + ' ' + "{{ lang._('quotas counted') }}") : "{{ lang._('nothing is counted or blocked') }}"));
            $cards.append(card(on && c.near ? 'warn' : '', 'fa-hourglass-half', "{{ lang._('Near the limit') }}",
                on ? count(c.near) : '-', data.near_percent + ' % ' + "{{ lang._('or more of a quota') }}"));
            $cards.append(card('', 'fa-bar-chart', "{{ lang._('Counted this cycle') }}", size(c.used),
                last.at ? "{{ lang._('last read') }}" + ' ' + when(last.at) + ' · ' + count(last.connections) + ' ' +
                    "{{ lang._('connections') }}" : "{{ lang._('not read yet') }}"));
            const error = data.error || null;
            $cards.append(card(error ? 'warn' : '', 'fa-exclamation-triangle', "{{ lang._('Last error') }}",
                error ? when(error.at) : "{{ lang._('none') }}", error ? error.message : ''));
            if (data.project && data.count_to_pf === false) {
                $cards.append(card('bad', 'fa-microchip', "{{ lang._('Hardware traffic') }}", "{{ lang._('not counted') }}",
                    "{{ lang._('XGS: Settings, Count hardware traffic in pf, is off: a connection in hardware is counted for its first packets only - 0.001 % of a 4.1 GB transfer in the lab.') }}"));
            }

            const alias = data.alias;
            /* the plugin's alias, not in XGS: Settings' cut list: taken out by the owner (recorded), or not
               put there yet - os-xgs-npu installed since the last Apply - when the plugin cuts itself */
            const unlisted = on && !!data.project && !!alias && alias.ours && !data.cut_listed;
            $('#qt-off').toggle(!on);
            $('#qt-project').toggle(on && !!data.project && !unlisted && data.cut_in_hardware !== false);
            $('#qt-project-pf').toggle(on && !!data.project && !unlisted && data.cut_in_hardware === false);
            $('#qt-alone').toggle(on && !data.project);
            $('#qt-backup').toggle(on && data.role === 'backup');
            $('#qt-unlisted').toggle(unlisted && !!data.cut_recorded);
            $('#qt-unlisted-new').toggle(unlisted && !data.cut_recorded);
            $('#qt-noalias').toggle(on && !alias);
            $('#qt-notours').toggle(on && !!alias && !alias.ours);
        }

        function refresh() {
            ajaxGet('/api/quota/service/status', {}, function (data) {
                draw(data);
                $('#grid-quotas').bootgrid('reload');
            });
        }

        /* The grid's rows are built by the API controller; the API escapes what it returns, so nothing here
           escapes it again. What each host used comes from the last status read. */
        $('#grid-quotas').UIBootgrid({
            search: '/api/quota/settings/search_quotas',
            get: '/api/quota/settings/get_quota/',
            set: '/api/quota/settings/set_quota/',
            add: '/api/quota/settings/add_quota/',
            del: '/api/quota/settings/del_quota/',
            toggle: '/api/quota/settings/toggle_quota/',
            commands: {
                reset: {
                    method: function () {
                        const uuid = $(this).data('row-id');
                        BootstrapDialog.confirm({
                            title: "{{ lang._('Reset the count') }}",
                            message: "{{ lang._('This quota\'s count of this cycle goes back to nothing now, and its host passes again if it was blocked.') }}",
                            type: BootstrapDialog.TYPE_WARNING,
                            btnOKLabel: "{{ lang._('Reset') }}",
                            callback: function (yes) {
                                if (yes) {
                                    ajaxCall('/api/quota/service/reset/' + uuid, {}, function () {
                                        refresh();
                                    });
                                }
                            }
                        });
                    },
                    classname: 'fa fa-fw fa-undo',
                    title: "{{ lang._('Reset the count') }}",
                    sequence: 300
                }
            },
            options: {
                formatters: {
                    host: function (column, row) {
                        const q = use[row.uuid];
                        let out = '<span dir="ltr">' + row.host + '</span>';
                        if (q && q.kind === 'mac') {
                            out += ' <span class="text-muted">' + (q.addresses.length ?
                                '<span dir="ltr">' + q.addresses.join(', ') + '</span>' : "{{ lang._('no address seen') }}") + '</span>';
                        }
                        return out;
                    },
                    volume: function (column, row) {
                        if (!row.volume) {
                            return '<span class="text-muted">-</span>';
                        }
                        const limit = Number(row.volume) * 1000000;
                        const q = use[row.uuid];
                        if (!q) {
                            return size(limit);
                        }
                        return size(q.used) + ' / ' + size(limit) + ' <span class="text-muted">' + share(q.used, limit) + '</span>';
                    },
                    minutes: function (column, row) {
                        if (!row.minutes) {
                            return '<span class="text-muted">-</span>';
                        }
                        const q = use[row.uuid];
                        return (q ? count(q.minutes) + ' / ' : '') + count(row.minutes) + ' ' + "{{ lang._('minutes') }}";
                    },
                    cycle: function (column, row) {
                        const q = use[row.uuid];
                        return row.cycle + (q && q.end ? ' <span class="text-muted">' + "{{ lang._('until') }}" + ' ' + when(q.end) + '</span>' : '');
                    },
                    state: function (column, row) {
                        const q = use[row.uuid];
                        if (!status || !status.enabled || !q) {
                            return '<span class="text-muted">' + states.off + '</span>';
                        }
                        if (q.state === 'over') {
                            const why = $.map(q.why || [], function (w) {
                                return reasons[w] || w;
                            }).join(', ');
                            return '<span class="text-danger">' + states.over + (why ? ' (' + why + ')' : '') + '</span> ' +
                                '<span class="text-muted">' + "{{ lang._('since') }}" + ' ' + when(q.over_at) + '</span>';
                        }
                        const cls = {'near': 'text-warning', 'own': 'text-warning', 'unreadable': 'text-danger'}[q.state] || 'text-muted';
                        return '<span class="' + cls + '">' + (states[q.state] || q.state) + '</span>' +
                            (q.state === 'near' ? ' <span class="text-muted">' + q.percent + ' %</span>' : '');
                    }
                }
            }
        });

        /* the cards, and the grid */
        $('#refreshAct').click(function () {
            refresh();
        });

        /* Apply: the alias, the filter and a read (reconfigure); from Settings the settings saved first */
        function apply($button, $progress, $result, save) {
            $button.prop('disabled', true);
            $progress.addClass('fa fa-spinner fa-pulse');
            const done = function () {
                $progress.removeClass('fa fa-spinner fa-pulse');
                $button.prop('disabled', false);
            };
            const go = function () {
                ajaxCall('/api/quota/service/reconfigure', {}, function (data) {
                    done();
                    const lines = (data && data.changes ? data.changes : []).concat(data && data.notes ? data.notes : [])
                        .concat(data && data.errors ? data.errors : []);
                    $result.attr('class', data && data.status === 'ok' ? 'text-muted' : 'alert alert-danger')
                        .text(plain(lines.length ? lines.join(' · ') : "{{ lang._('Nothing to change in the alias.') }}")).show();
                    refresh();
                });
            };
            if (save) {
                saveFormToEndpoint('/api/quota/settings/set', 'frm_general', go, false, done);
            } else {
                go();
            }
        }

        mapDataToFormUI({'frm_general': '/api/quota/settings/get'}).done(function () {
            $('.selectpicker').selectpicker('refresh');
        });
        $('#applyAct').click(function () {
            apply($(this), $('#frm_general_progress'), $('#qt-result'), true);
        });
        $('#applyQuotasAct').click(function () {
            apply($(this), $('#qt-quotas-progress'), $('#qt-quotas-result'), false);
        });

        cards_wait('#qt-cards', ["{{ lang._('Over quota') }}", "{{ lang._('Near the limit') }}", "{{ lang._('Counted this cycle') }}",
            "{{ lang._('Last error') }}"]);
        refresh();
        keep_tab();
    });
</script>

<div class="xgs-cards xgs-top" id="qt-cards"></div>
<div class="text-muted clearfix qt-quiet" style="padding: 0 0 10px;">
    <button id="refreshAct" class="btn btn-default btn-xs pull-right" type="button" title="{{ lang._('Refresh') }}"><i class="fa fa-fw fa-refresh"></i></button>
    <span id="qt-off" style="display: none;">{{ lang._('Quotas is off: nothing is counted and no host is blocked.') }}</span>
    <span id="qt-project" style="display: none;">{{ lang._('os-xgs-npu is installed: a connection in hardware is counted through its pf states, and a host that goes over its quota has its open connections cut by XGS: Settings within a minute, in hardware first.') }}</span>
    <span id="qt-project-pf" style="display: none;">{{ lang._('os-xgs-npu is installed: a connection in hardware is counted through its pf states, and a host that goes over its quota has its open connections cut by XGS: Settings within a minute.') }}</span>
    <span id="qt-alone" style="display: none;">{{ lang._('Without os-xgs-npu pf alone carries the traffic: a host that goes over its quota has its open connections cut at once.') }}</span>
    <span id="qt-backup" class="text-warning" style="display: none;">{{ lang._('This firewall is a CARP backup: the master counts and blocks, and nothing is counted here.') }}</span>
    <span id="qt-unlisted" class="text-warning" style="display: none;">{{ lang._('quota_over is not in the cut list of XGS: Settings: a host that goes over its quota keeps the connections it has open.') }}</span>
    <span id="qt-unlisted-new" class="text-warning" style="display: none;">{{ lang._('quota_over is not in the cut list of XGS: Settings yet - Apply puts it there. Until then this plugin cuts the open connections of a host that goes over its quota itself, at once.') }}</span>
    <span id="qt-noalias" class="text-warning" style="display: none;">{{ lang._('The alias quota_over is not made yet: Apply makes it. Until then no host is blocked.') }}</span>
    <span id="qt-notours" class="text-warning" style="display: none;">{{ lang._('An alias named quota_over that is not this plugin\'s is in Firewall: Aliases: no host is blocked until it is renamed.') }}</span>
</div>

<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#quotas">{{ lang._('Quotas') }}</a></li>
    <li><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
</ul>

<div class="tab-content content-box">
    <div id="quotas" class="tab-pane active">
        <table id="grid-quotas" class="table table-condensed table-hover table-striped" data-editDialog="DialogQuota">
            <thead>
                <tr>
                    <th data-column-id="uuid" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                    <th data-column-id="enabled" data-width="6em" data-type="boolean" data-formatter="rowtoggle">{{ lang._('Enabled') }}</th>
                    <th data-column-id="host" data-type="string" data-formatter="host">{{ lang._('Host') }}</th>
                    <th data-column-id="description" data-type="string">{{ lang._('Description') }}</th>
                    <th data-column-id="volume" data-type="string" data-formatter="volume" data-sortable="false">{{ lang._('Volume') }}</th>
                    <th data-column-id="minutes" data-type="string" data-formatter="minutes" data-sortable="false">{{ lang._('Time') }}</th>
                    <th data-column-id="cycle" data-type="string" data-formatter="cycle">{{ lang._('Cycle') }}</th>
                    <th data-column-id="state" data-type="string" data-formatter="state" data-sortable="false">{{ lang._('This cycle') }}</th>
                    <th data-column-id="commands" data-width="9em" data-formatter="commands" data-sortable="false">{{ lang._('Commands') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
            <tfoot>
                <tr>
                    <td></td>
                    <td>
                        <button data-action="add" type="button" class="btn btn-xs btn-primary"><span class="fa fa-plus fa-fw"></span></button>
                        <button data-action="deleteSelected" type="button" class="btn btn-xs btn-default"><span class="fa fa-trash-o fa-fw"></span></button>
                    </td>
                </tr>
            </tfoot>
        </table>
        <div class="text-muted qt-note">
            {{ lang._('Each host is counted from pf\'s states once a minute: every byte of its connections, to and from the firewall itself too, and what the coprocessor forwards where os-xgs-npu gives pf its counts. A host can go past its limit by what it moves in up to a minute before it is blocked. Over its quota, it reaches DNS and this page on the firewall and nothing else, until its cycle starts again or its count is reset here.') }}
        </div>
        <div class="text-muted qt-note">
            {{ lang._('Changes here are counted from the next minute\'s read, or at once with Apply.') }}
        </div>
        <div class="qt-foot">
            <button id="applyQuotasAct" class="btn btn-primary" type="button"><b>{{ lang._('Apply') }}</b> <i id="qt-quotas-progress"></i></button>
            <div id="qt-quotas-result" style="display: none; padding-top: 10px;"></div>
        </div>
    </div>
    <div id="settings" class="tab-pane">
        {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general', 'apply_btn_id': 'applyAct']) }}
        <div style="padding: 0 15px 15px;"><div id="qt-result" style="display: none;"></div></div>
    </div>
</div>

{{ partial("layout_partials/base_dialog", ['fields': formDialogQuota, 'id': 'DialogQuota', 'label': lang._('Edit quota')]) }}
{{ partial("OPNsense/Quota/credit") }}
