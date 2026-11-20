<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The alias behind Quotas' block table (settled point 5): quota_over, of type External, written in
 * config.xml through OPNsense's own Alias model, as os-blocklists and os-useridentity write theirs - the
 * kind os-xgs-npu's lists_cut.py can find, which resolves XGS: Settings' cut list from config.xml. The
 * plugin fills its pf table itself (scripts/quota/enforce.py); OPNsense declares it and leaves what it
 * holds alone.
 *
 * It is the plugin's when its name is quota_over and its description begins 'Quotas:'. An alias of that
 * name that is not the plugin's is the owner's, and is never touched: nothing is blocked then, and the
 * page says so.
 *
 * Where os-xgs-npu is installed its cut list holds the alias too (settled point 6). A host that goes over
 * its quota has its open connections cut by the plugin's own read that blocks it, at once, in hardware
 * first where "Cut in hardware" is on (scripts/quota/account.py, cut_here()); lists_cut.py's next minute
 * then finds nothing left, or what came in between. It is put there once and recorded in the plugin's
 * settings (general.cut_added), as os-useridentity records its own: one the owner takes out of XGS:
 * Settings stays out - lists_cut.py would take every address the table holds as new, and cut it - and the
 * plugin's read then cuts nothing either.
 */

namespace OPNsense\Quota;

class Aliases
{
    const NAME = 'quota_over';
    const DESCRIPTION = 'Quotas: hosts over their quota';
    const OWNED = 'Quotas:';

    /**
     * The alias is this plugin's: its name and its description both say so.
     */
    public static function owned($name, $description)
    {
        return (string)$name === self::NAME && strpos((string)$description, self::OWNED) === 0;
    }

    /**
     * $config with the plugin's own entry taken out of XGS: Settings' cut list, and without the plugin's
     * own section, whose record of the cut list holds the alias's uuid: neither is something else naming
     * or holding the alias.
     */
    public static function references($config, $uuid)
    {
        $config = preg_replace('#<Quota\b[^>]*>.*?</Quota>#s', '<Quota/>', (string)$config);
        return preg_replace_callback('/<cut_lists>([^<]*)<\/cut_lists>/', function ($m) use ($uuid) {
            $kept = array_diff(array_filter(explode(',', $m[1])), [(string)$uuid]);
            return '<cut_lists>' . implode(',', $kept) . '</cut_lists>';
        }, (string)$config);
    }

    /**
     * The model's alias made to say what the plugin wants - there, External, switched on, while $on; not
     * there while off - and ['changes' => what changed, 'notes' => what was left as it is and why], one
     * line each. No longer wanted, the plugin's alias is removed; when something else in the configuration
     * names it or holds its uuid - a rule of the owner's, a setting - it is switched off instead, as
     * os-blocklists does, so nothing of the owner's is left pointing at nothing. $config is config.xml's
     * text as references() gives it. Nothing is saved here.
     */
    public static function reconcile($model, $config, $on)
    {
        $changes = [];
        $notes = [];
        $node = null;
        $uuid = null;
        foreach (iterator_to_array($model->aliases->alias->iterateItems()) as $key => $alias) {
            if ((string)$alias->name === self::NAME) {
                $node = $alias;
                $uuid = (string)$key;
                break;
            }
        }
        if ($node !== null && !self::owned($node->name, $node->description)) {
            $notes[] = self::NAME . ': an alias of this name is not this plugin\'s - left as it is, and no host is blocked';
            return ['changes' => $changes, 'notes' => $notes];
        }
        if (!$on) {
            if ($node === null) {
                return ['changes' => $changes, 'notes' => $notes];
            }
            $named = preg_match_all('/\b' . preg_quote(self::NAME, '/') . '\b/', (string)$config) > 1;
            $held = substr_count((string)$config, (string)$uuid) > 1;
            if ($named || $held) {
                if ((string)$node->enabled !== '0') {
                    $node->enabled = '0';
                    $changes[] = self::NAME . ': no longer wanted, but named elsewhere in the configuration - switched off, not removed';
                }
            } else {
                $model->aliases->alias->del($uuid);
                $changes[] = self::NAME . ': removed';
            }
            return ['changes' => $changes, 'notes' => $notes];
        }
        $values = ['enabled' => '1', 'type' => 'external', 'description' => self::DESCRIPTION];
        if ($node === null) {
            $node = $model->aliases->alias->Add();
            $node->setNodes(['name' => self::NAME] + $values);
            $changes[] = self::NAME . ': added';
            return ['changes' => $changes, 'notes' => $notes];
        }
        $was = [];
        foreach (array_keys($values) as $field) {
            $was[$field] = (string)$node->$field;
        }
        if ($was !== $values) {
            $node->setNodes($values);
            $changes[] = self::NAME . ': updated';
        }
        return ['changes' => $changes, 'notes' => $notes];
    }

    /**
     * The plugin's alias in the model: ['uuid' => ..., 'enabled' => bool], or null when it has none.
     */
    public static function ours($model)
    {
        foreach ($model->aliases->alias->iterateItems() as $uuid => $alias) {
            if (self::owned((string)$alias->name, (string)$alias->description)) {
                return ['uuid' => (string)$uuid, 'enabled' => (string)$alias->enabled === '1'];
            }
        }
        return null;
    }

    /**
     * XGS: Settings' cut list as it should be, and the plugin's record of what it put there: [list,
     * record]. $uuid is the plugin's alias's - as it is now, or as it was before this Apply took it out -
     * and $live whether it is there and switched on. The owner's entries stay as they are, in their
     * order. The plugin's alias, live, goes in once - when the record does not hold it yet: made now, or
     * made before os-xgs-npu was installed - and is recorded; one the record holds is left as the owner
     * left it. Not live, it leaves the list and the record both, so wanted again it goes back; its uuid
     * cannot stay in the list once the alias is gone, which the cut list's relation field would refuse.
     */
    public static function cutLists(array $current, $uuid, $live, array $added = [])
    {
        $out = [];
        foreach ($current as $entry) {
            if ($entry !== '' && ($entry !== $uuid || $live) && !in_array($entry, $out, true)) {
                $out[] = $entry;
            }
        }
        if (!$live || $uuid === null || $uuid === '') {
            return [$out, []];
        }
        if (!in_array($uuid, $added, true) && !in_array($uuid, $out, true)) {
            $out[] = $uuid;
        }
        return [$out, [$uuid]];
    }
}
