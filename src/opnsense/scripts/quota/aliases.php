#!/usr/local/bin/php
<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * Make the firewall's alias quota_over say what Settings says (library OPNsense\Quota\Aliases): an
 * External alias while Quotas is on, none of this plugin's while it is off. Where os-xgs-npu is
 * installed, its cut list - XGS: Settings, "Cut open connections when listed" - then holds it, beside
 * the owner's own entries, which stay as they are (settled point 6): put there once and recorded in the
 * plugin's settings (general.cut_added), so taken out by the owner it stays out. The plugin's own read
 * cuts the connections of a host that goes over its quota, with os-xgs-npu or without it (account.py).
 *
 * Nothing is saved unless the models take every change; the configuration is saved once.
 *
 *   aliases.php            print a JSON summary; the page's Apply then reloads the filter
 *   aliases.php --remove   the plugin's alias taken out, and out of the cut list (its removal)
 */

require_once('script/load_phalcon.php');

use OPNsense\Core\Config;
use OPNsense\Firewall\Alias;
use OPNsense\Quota\Aliases;
use OPNsense\Quota\Quota;

function answer($result)
{
    echo json_encode($result) . "\n";
    exit(0);
}

$settings = new Quota();
$on = !in_array('--remove', $argv, true) && (string)$settings->general->enabled === '1';

$model = new Alias();
/* config.xml's text, read for what else names the alias; the tests give it another */
$config = (string)@file_get_contents(getenv('QUOTA_CONFIG') ?: '/conf/config.xml');
$before = Aliases::ours($model);
$done = Aliases::reconcile($model, Aliases::references($config, $before['uuid'] ?? ''), $on);
$changes = $done['changes'];

$messages = [];
foreach ($model->performValidation() as $message) {
    $messages[] = $message->getField() . ': ' . $message->getMessage();
}
if (!empty($messages)) {
    answer(['status' => 'failed', 'changes' => [], 'errors' => $messages]);
}
if (!empty($changes)) {
    $model->serializeToConfig();
}

/* XGS: Settings' cut list, where os-xgs-npu is installed - read after the alias is in the configuration,
   so the uuid of one just added is known to its relation field */
$cut = ['xgs' => false, 'changed' => false, 'listed' => false];
$recorded = false;
if (class_exists('OPNsense\XGS\XGS')) {
    $xgs = new \OPNsense\XGS\XGS();
    $node = $xgs->getNodeByReference('general.cut_lists');
    if ($node !== null) {
        $cut['xgs'] = true;
        $now = Aliases::ours($model);
        $uuid = $now['uuid'] ?? ($before['uuid'] ?? null);
        $current = array_values(array_filter(explode(',', (string)$node)));
        /* what the plugin put in the cut list itself: taken out by the owner, it is not put back */
        $added = array_values(array_filter(explode(',', (string)$settings->general->cut_added)));
        [$after, $record] = Aliases::cutLists($current, $uuid, $now !== null && $now['enabled'], $added);
        if ($record !== $added) {
            $settings->general->cut_added = implode(',', $record);
            $refused = [];
            foreach ($settings->performValidation() as $message) {
                $refused[] = $message->getField() . ': ' . $message->getMessage();
            }
            if (!empty($refused)) {
                answer(['status' => 'failed', 'changes' => [], 'errors' => $refused]);
            }
            $settings->serializeToConfig();
            $recorded = true;
        }
        if ($after !== $current) {
            $node->setValue(implode(',', $after));
            $refused = [];
            foreach ($xgs->performValidation() as $message) {
                $refused[] = $message->getField() . ': ' . $message->getMessage();
            }
            if (!empty($refused)) {
                answer(['status' => 'failed', 'changes' => [], 'errors' => $refused]);
            }
            $xgs->serializeToConfig();
            $cut['changed'] = true;
            $changes[] = 'XGS: Settings, cut open connections when listed: ' .
                (in_array($uuid, $after, true) ? 'quota_over added' : 'quota_over taken out');
        }
        $cut['listed'] = $uuid !== null && in_array($uuid, $after, true);
    }
}

if (!empty($changes) || $recorded) {
    Config::getInstance()->save();
}
answer(['status' => 'ok', 'enabled' => $on, 'changes' => $changes, 'notes' => $done['notes'], 'cut' => $cut]);
