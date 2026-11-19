<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The block of the hosts over their quota, registered at every filter reload - never among the owner's
 * rules in Firewall: Rules, so turning the plugin off or removing it leaves nothing behind there, as
 * os-blocklists' block rules. Priority 1, quick, floating, both families, on the table quota_over
 * (scripts/quota/enforce.py fills it):
 *
 *   pass  in  from <quota_over> to (self) port 53, TCP and UDP     DNS on the firewall
 *   pass  in  from <quota_over> to (self) port <the web GUI's>     the page that says why
 *   block in  from <quota_over>                                    everything else it sends
 *   block in  to <quota_over>                                      and every new connection to it
 *
 * What a host over its quota can still reach (settled point 7's starred choice): DNS and the web GUI on
 * the firewall itself, so nobody - the owner on his own PC among them - is locked out of the page that
 * says why. A block at priority 1 comes before the anti-lockout rule (priority 5, filter.lib.inc), which
 * would otherwise not save it. Core's own priority-1 rules come first - DHCP and IPv6's neighbour
 * discovery among them - so the host keeps its address and its link. The web GUI's ports are core's own
 * anti-lockout choice without SSH: its port, or 443 or 80 by its protocol, and 80 too when HTTPS
 * redirects from it.
 *
 * A block stops new connections only; the ones already open are cut by the plugin's run (enforce.py).
 *
 * Registered only while the plugin is on and the alias quota_over is its own - External, switched on,
 * described 'Quotas:'. One of that name that is the owner's is never blocked: its addresses are his.
 * A rule this hook cannot register must not stop the ruleset from loading (os-xgs-npu issue 969): the hook
 * runs inside filter_configure_sync(), and at boot an error escaping it leaves the machine at a
 * single-user prompt. So anything that goes wrong is said in the system log and the reload goes on.
 * Settings are read out of $config, not through the plugin's model, as os-useridentity's hook reads its
 * own; the alias through OPNsense's Alias model, as os-blocklists' hook does.
 */

function quota_general()
{
    global $config;

    $general = $config['OPNsense']['Quota']['general'] ?? [];
    return is_array($general) ? $general : [];
}

function quota_enabled()
{
    return (quota_general()['enabled'] ?? '0') === '1';
}

/*
 * The web GUI's ports, as core's filter_core_get_antilockout() gives them, without SSH's.
 */
function quota_gui_ports()
{
    global $config;

    $webgui = $config['system']['webgui'] ?? [];
    $webgui = is_array($webgui) ? $webgui : [];
    $https = ($webgui['protocol'] ?? '') == 'https';
    $ports = [empty($webgui['port']) ? ($https ? '443' : '80') : (string)$webgui['port']];
    if ($https && !isset($webgui['disablehttpredirect'])) {
        $ports[] = '80';
    }
    $ports = array_filter($ports, function ($port) {
        return ctype_digit($port) && (int)$port >= 1 && (int)$port <= 65535;
    });
    return array_values(array_unique($ports));
}

/*
 * Whether quota_over is the plugin's own alias, External and switched on.
 */
function quota_alias_ready()
{
    if (!class_exists('OPNsense\Firewall\Alias')) {
        return false;
    }
    foreach ((new \OPNsense\Firewall\Alias())->aliases->alias->iterateItems() as $alias) {
        if ((string)$alias->name !== 'quota_over') {
            continue;
        }
        return strpos((string)$alias->description, 'Quotas:') === 0 && (string)$alias->enabled === '1' &&
            (string)$alias->type === 'external';
    }
    return false;
}

function quota_firewall($fw)
{
    if (!quota_enabled()) {
        return $fw;
    }
    try {
        if (!quota_alias_ready()) {
            syslog(LOG_NOTICE, 'quota: the alias quota_over is not this plugin\'s, or not there yet - Apply makes it: no host is blocked');
            return $fw;
        }
        $table = '<quota_over>';
        foreach (['inet', 'inet6'] as $family) {
            $fw->registerFilterRule(1, [
                'ipprotocol' => $family,
                'protocol' => 'tcp/udp',
                'from' => $table,
                'to' => '(self)',
                'to_port' => '53',
                'direction' => 'in',
                'type' => 'pass',
                'statetype' => 'keep',
                'quick' => true,
                'descr' => 'Quotas: DNS on the firewall, for a host over its quota',
            ]);
            foreach (quota_gui_ports() as $port) {
                $fw->registerFilterRule(1, [
                    'ipprotocol' => $family,
                    'protocol' => 'tcp',
                    'from' => $table,
                    'to' => '(self)',
                    'to_port' => $port,
                    'direction' => 'in',
                    'type' => 'pass',
                    'statetype' => 'keep',
                    'quick' => true,
                    'descr' => 'Quotas: the web GUI, for a host over its quota',
                ]);
            }
            $fw->registerFilterRule(1, [
                'ipprotocol' => $family,
                'from' => $table,
                'direction' => 'in',
                'type' => 'block',
                'quick' => true,
                'descr' => 'Quotas: a host over its quota',
            ]);
            $fw->registerFilterRule(1, [
                'ipprotocol' => $family,
                'to' => $table,
                'direction' => 'in',
                'type' => 'block',
                'quick' => true,
                'descr' => 'Quotas: to a host over its quota',
            ]);
        }
    } catch (\Throwable $e) {
        syslog(LOG_ERR, 'quota: the block rules were left out: ' . $e->getMessage());
    }

    return $fw;
}
