<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The block of the hosts over their quota, registered at every filter reload - never among the owner's
 * rules in Firewall: Rules, so turning the plugin off or removing it leaves nothing behind there, as
 * os-blocklists' block rules. Priority 1, quick, floating, both families, on the table quota_over
 * (scripts/quota/enforce.py fills it). Every one of them a block:
 *
 *   block in from <quota_over> to ! (self)                everything it sends past the firewall
 *   block in proto tcp from <quota_over> to (self) port   every TCP port of the firewall but DNS's and
 *                                                         the web GUI's, a range a rule
 *   block in proto udp from <quota_over> to (self) port   every UDP port of it but DNS's
 *   block in proto icmp (ipv6-icmp) from <quota_over>     ICMP to the firewall, and IP in IP (4), IPv6
 *            to (self), and proto 4, 41, 47, 50, 51       in IP (41), GRE (47), ESP (50) and AH (51)
 *   block in to <quota_over>                              and every new connection to it
 *
 * What a host over its quota keeps (settled point 7's starred choice) is DNS and the web GUI on the
 * firewall itself, and nothing else - kept, not given: those are left out of the block, so what decides
 * them is what decided them before the host went over - core's anti-lockout rule (priority 5, its one
 * interface, none when "Disable anti-lockout" is set) and the owner's own rules. So nobody - the owner on
 * his own PC among them - is locked out by a quota, and a host the owner's rules keep away from the
 * firewall (a guest network) is not let in by going over one. A pass here would come before both: at
 * priority 1 it would open DNS and the GUI on every address of the firewall, from every interface.
 *
 * Core's own priority-1 rules come first - DHCP and IPv6's neighbour discovery among them - so the host
 * keeps its address and its link. The web GUI's ports are core's own anti-lockout choice without SSH: its
 * port, or 443 or 80 by its protocol, and 80 too when HTTPS redirects from it. TCP and UDP port 0 is
 * blocked by core's own rule. Another protocol addressed to the firewall itself is left to the owner's
 * rules: none of them takes a host's traffic further, as a tunnel's would.
 *
 * A port forward whose filter rule association is Pass is written "rdr pass": pf checks no filter rule
 * for it, these blocks among them, so what such a forward lets in is outside the block (README).
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

/*
 * The ports of 1 to 65535 that are not among $kept, as OPNsense's FilterRule takes them - one port, or
 * one range 'from:to', a rule - in order.
 */
function quota_other_ports(array $kept)
{
    $kept = array_values(array_unique(array_map('intval', $kept)));
    sort($kept);
    $out = [];
    $from = 1;
    foreach ($kept as $port) {
        if ($port < $from || $port > 65535) {
            continue;
        }
        if ($port > $from) {
            $out[] = $port - 1 > $from ? $from . ':' . ($port - 1) : (string)$from;
        }
        $from = $port + 1;
    }
    if ($from <= 65535) {
        $out[] = $from < 65535 ? $from . ':65535' : '65535';
    }
    return $out;
}

/*
 * One of the blocks: priority 1, inbound, quick, floating, its family, described.
 */
function quota_block($fw, $family, array $rule, $descr)
{
    $fw->registerFilterRule(1, array_merge([
        'ipprotocol' => $family,
        'direction' => 'in',
        'type' => 'block',
        'quick' => true,
    ], $rule, ['descr' => 'Quotas: ' . $descr]));
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
        $from = ['from' => '<quota_over>'];
        $self = $from + ['to' => '(self)'];
        $tcp = quota_other_ports(array_merge(['53'], quota_gui_ports()));
        $udp = quota_other_ports(['53']);
        foreach (['inet', 'inet6'] as $family) {
            quota_block($fw, $family, $self + ['to_not' => true], 'a host over its quota');
            foreach ($tcp as $ports) {
                quota_block($fw, $family, $self + ['protocol' => 'tcp', 'to_port' => $ports],
                    'a host over its quota, to the firewall but DNS and the web GUI');
            }
            foreach ($udp as $ports) {
                quota_block($fw, $family, $self + ['protocol' => 'udp', 'to_port' => $ports],
                    'a host over its quota, to the firewall but DNS');
            }
            /* ICMP; IP in IP, IPv6 in IP, GRE, ESP and AH - a tunnel to the firewall would carry it on */
            foreach ([$family == 'inet' ? 'icmp' : 'ipv6-icmp', '4', '41', '47', '50', '51'] as $protocol) {
                quota_block($fw, $family, $self + ['protocol' => $protocol],
                    'a host over its quota, to the firewall');
            }
            quota_block($fw, $family, ['to' => '<quota_over>'], 'to a host over its quota');
        }
    } catch (\Throwable $e) {
        syslog(LOG_ERR, 'quota: the block rules were left out: ' . $e->getMessage());
    }

    return $fw;
}
