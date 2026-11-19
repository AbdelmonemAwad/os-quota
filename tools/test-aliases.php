<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The alias behind the block table (library OPNsense\Quota\Aliases, and scripts/quota/aliases.php that
 * runs it), with stand-ins for what they reach of OPNsense: the Alias model - its aliases, Add(), del(),
 * setNodes(), performValidation(), serializeToConfig() - Config's save(), the plugin's own model and
 * os-xgs-npu's XGS model, whose cut list is a relation to aliases and refuses a uuid no alias has.
 *
 * What is checked: on, quota_over made External, switched on and described as the plugin's, refreshed when
 * changed, the owner's alias of that name left with a note; off, removed when nothing names it, switched off
 * when a rule does, the plugin's own section and cut-list entry not counted as naming it; XGS: Settings' cut
 * list holding it after the owner's entries, kept as they are, put there once and recorded, not put back
 * once the owner took it out, out of the list and the record when off; and aliases.php run as configd runs
 * it - saving once, nothing when nothing changed, nothing when a model refuses, no cut list without
 * os-xgs-npu, --remove.
 *
 *   php tools/test-aliases.php
 */

namespace OPNsense\Firewall {
    class AliasNode
    {
        public $fields = [];

        public function __construct($fields = [])
        {
            $this->fields = $fields;
        }

        public function __get($name)
        {
            return (string)($this->fields[$name] ?? '');
        }

        public function __set($name, $value)
        {
            $this->fields[$name] = (string)$value;
        }

        public function setNodes($values)
        {
            foreach ($values as $name => $value) {
                $this->fields[$name] = (string)$value;
            }
        }
    }

    class AliasList
    {
        public $nodes = [];
        public static $next = 100;

        public function iterateItems()
        {
            foreach ($this->nodes as $uuid => $node) {
                yield $uuid => $node;
            }
        }

        public function Add()
        {
            $uuid = sprintf('00000000-0000-4000-8000-%012d', self::$next++);
            return $this->nodes[$uuid] = new AliasNode();
        }

        public function del($uuid)
        {
            unset($this->nodes[$uuid]);
        }
    }

    class Alias
    {
        public static $given = [];
        public $aliases;

        public function __construct()
        {
            $list = new AliasList();
            foreach (self::$given as $uuid => $fields) {
                $list->nodes[$uuid] = new AliasNode($fields);
            }
            $this->aliases = (object)['alias' => $list];
        }
    }
}

namespace {
    $root = dirname(__DIR__);
    require $root . '/src/opnsense/mvc/app/library/OPNsense/Quota/Aliases.php';

    use OPNsense\Firewall\Alias;
    use OPNsense\Quota\Aliases;

    $failed = 0;
    $checks = 0;

    function check($ok, $what)
    {
        global $failed, $checks;
        $checks++;
        if (!$ok) {
            $failed++;
            echo "FAIL $what\n";
        } else {
            echo "ok   $what\n";
        }
    }

    const OURS = ['enabled' => '1', 'name' => 'quota_over', 'type' => 'external', 'description' => 'Quotas: hosts over their quota'];

    /* made, refreshed, the owner's left */
    Alias::$given = ['o1' => ['enabled' => '1', 'name' => 'mine', 'type' => 'host', 'description' => 'my list']];
    $model = new Alias();
    $done = Aliases::reconcile($model, '', true);
    $made = null;
    foreach ($model->aliases->alias->nodes as $uuid => $node) {
        if ($node->name === 'quota_over') {
            $made = $node->fields;
        }
    }
    check($done['changes'] === ['quota_over: added'] && $made === ['name' => 'quota_over'] + array_slice(OURS, 0, 1) +
        ['type' => 'external', 'description' => 'Quotas: hosts over their quota'], 'on, no alias: quota_over added, External, on, the plugin\'s');
    check(count($model->aliases->alias->nodes) === 2, 'the owner\'s other alias left');
    Alias::$given = ['q1' => array_merge(OURS, ['enabled' => '0'])];
    $model = new Alias();
    $done = Aliases::reconcile($model, '', true);
    check($done['changes'] === ['quota_over: updated'] && $model->aliases->alias->nodes['q1']->enabled === '1',
        'on, the plugin\'s alias switched off: switched on');
    $done = Aliases::reconcile($model, '', true);
    check($done['changes'] === [], 'on again, as it should be: nothing');
    Alias::$given = ['b1' => ['enabled' => '1', 'name' => 'quota_over', 'type' => 'host', 'description' => 'my own']];
    $model = new Alias();
    $done = Aliases::reconcile($model, '', true);
    check($done['changes'] === [] && count($done['notes']) === 1 && strpos($done['notes'][0], 'not this plugin') !== false &&
        $model->aliases->alias->nodes['b1']->type === 'host', 'an alias of that name that is the owner\'s: left, said in the notes');
    $done = Aliases::reconcile($model, '', false);
    check(isset($model->aliases->alias->nodes['b1']) && $done['changes'] === [], '... and off, not removed either');
    check(Aliases::owned('quota_over', 'Quotas: x') && !Aliases::owned('quota_over', 'x') && !Aliases::owned('other', 'Quotas: x'),
        'the plugin\'s by its name and its description together');

    /* off */
    Alias::$given = ['q1' => OURS];
    $model = new Alias();
    $config = '<alias uuid="q1"><name>quota_over</name></alias><Quota><general><cut_added>q1</cut_added></general></Quota>'
        . '<cut_lists>o9,q1</cut_lists>';
    $done = Aliases::reconcile($model, Aliases::references($config, 'q1'), false);
    check($done['changes'] === ['quota_over: removed'] && !isset($model->aliases->alias->nodes['q1']),
        'off: removed - its own section and its own entry in the cut list are no one else\'s');
    Alias::$given = ['q1' => OURS];
    $model = new Alias();
    $config .= '<rule><source><network>quota_over</network></source></rule>';
    $done = Aliases::reconcile($model, Aliases::references($config, 'q1'), false);
    check($done['changes'] === ['quota_over: no longer wanted, but named elsewhere in the configuration - switched off, not removed']
        && $model->aliases->alias->nodes['q1']->enabled === '0', 'off, a rule of the owner\'s naming it: switched off, not removed');
    Alias::$given = [];
    check(Aliases::reconcile(new Alias(), '', false) === ['changes' => [], 'notes' => []], 'off, no alias: nothing');
    check(Aliases::references('<a/><Quota version="1.0.0"><general><cut_added>q1</cut_added></general></Quota><cut_lists>o9,q1,o8</cut_lists>', 'q1')
        === '<a/><Quota/><cut_lists>o9,o8</cut_lists>', 'what is read for references: the plugin\'s section and its cut entry left out');

    /* the cut list */
    check(Aliases::cutLists(['o1', 'o2', 'o1', ''], 'q1', true) === [['o1', 'o2', 'q1'], ['q1']],
        'the cut list: the owner\'s entries kept in their order, once; the plugin\'s added after them and recorded');
    check(Aliases::cutLists(['o1', 'q1'], 'q1', true, ['q1']) === [['o1', 'q1'], ['q1']], 'there and recorded: nothing changes');
    check(Aliases::cutLists(['o1'], 'q1', true, ['q1']) === [['o1'], ['q1']],
        'recorded, the owner took it out: not put back - lists_cut.py would cut every host it holds as new');
    check(Aliases::cutLists(['o1', 'q1'], 'q1', false, ['q1']) === [['o1'], []], 'off: out of the list and the record');
    check(Aliases::cutLists(['o1', 'q1'], null, false, []) === [['o1', 'q1'], []], 'no alias of the plugin\'s known: the list as it is');

    /* aliases.php, run as configd runs it */
    $tmp = sys_get_temp_dir() . '/test-quota-aliases.' . getmypid();
    @mkdir($tmp . '/script', 0755, true);
    $state = $tmp . '/state.json';
    file_put_contents($tmp . '/script/load_phalcon.php', '<?php
namespace OPNsense\Base\Messages { class Message { private $m; private $f;
    public function __construct($m, $f) { $this->m = $m; $this->f = $f; }
    public function getMessage() { return $this->m; } public function getField() { return $this->f; } } }
namespace OPNsense\Firewall {
    class AliasNode { public $fields = []; public function __construct($f = []) { $this->fields = $f; }
        public function __get($n) { return (string)($this->fields[$n] ?? ""); }
        public function __set($n, $v) { $this->fields[$n] = (string)$v; }
        public function setNodes($v) { foreach ($v as $k => $x) { $this->fields[$k] = (string)$x; } } }
    class AliasList { public $nodes = []; public function iterateItems() { foreach ($this->nodes as $u => $n) { yield $u => $n; } }
        public function Add() { $u = "n" . (count($this->nodes) + 100); return $this->nodes[$u] = new AliasNode(); }
        public function del($u) { unset($this->nodes[$u]); } }
    class Alias { public $aliases;
        public function __construct() { $l = new AliasList(); $s = json_decode((string)@file_get_contents(getenv("STATE")), true);
            foreach (($s["aliases"] ?? []) as $u => $f) { $l->nodes[$u] = new AliasNode($f); } $this->aliases = (object)["alias" => $l]; }
        public function performValidation() { $o = [];
            foreach ($this->aliases->alias->nodes as $u => $x) { if ($x->name === "") { $o[] = new \OPNsense\Base\Messages\Message("A value is required.", "aliases.alias.$u.name"); }
                if (!in_array($x->type, ["host", "network", "external", "urltable"], true)) { $o[] = new \OPNsense\Base\Messages\Message("Option not in list.", "aliases.alias.$u.type"); } }
            if (getenv("REFUSE") === "alias") { $o[] = new \OPNsense\Base\Messages\Message("refused", "aliases.alias"); } return $o; }
        public function serializeToConfig() { $s = json_decode((string)@file_get_contents(getenv("STATE")), true) ?: [];
            $s["aliases"] = []; foreach ($this->aliases->alias->nodes as $u => $n) { $s["aliases"][$u] = $n->fields; }
            file_put_contents(getenv("STATE"), json_encode($s)); } } }
namespace OPNsense\Quota {
    class Quota { public $general;
        public function __construct() { $s = json_decode((string)@file_get_contents(getenv("STATE")), true);
            $this->general = (object)["enabled" => $s["enabled"] ?? "0", "cut_added" => $s["cut_added"] ?? ""]; }
        public function performValidation() { return []; }
        public function serializeToConfig() { $s = json_decode((string)@file_get_contents(getenv("STATE")), true);
            $s["cut_added"] = (string)$this->general->cut_added; file_put_contents(getenv("STATE"), json_encode($s)); } } }
namespace OPNsense\XGS {
    if (getenv("XGS") === "1") {
        class Node { public $value; public function __construct($v) { $this->value = $v; }
            public function __toString() { return $this->value; } public function setValue($v) { $this->value = $v; } }
        class XGS { public $node;
            public function __construct() { $s = json_decode((string)@file_get_contents(getenv("STATE")), true);
                $this->node = new Node($s["cut_lists"] ?? ""); }
            public function getNodeByReference($r) { return $r === "general.cut_lists" ? $this->node : null; }
            public function performValidation() { $s = json_decode((string)@file_get_contents(getenv("STATE")), true); $o = [];
                foreach (array_filter(explode(",", $this->node->value)) as $u) {
                    if (!isset($s["aliases"][$u])) { $o[] = new \OPNsense\Base\Messages\Message("Option not in list.", "general.cut_lists"); } }
                return $o; }
            public function serializeToConfig() { $s = json_decode((string)@file_get_contents(getenv("STATE")), true);
                $s["cut_lists"] = $this->node->value; file_put_contents(getenv("STATE"), json_encode($s)); } } } }
namespace OPNsense\Core { class Config { public static function getInstance() { return new self(); }
    public function save() { $s = json_decode((string)file_get_contents(getenv("STATE")), true);
        $s["saved"] = ($s["saved"] ?? 0) + 1; file_put_contents(getenv("STATE"), json_encode($s)); } } }
namespace { require "' . $root . '/src/opnsense/mvc/app/library/OPNsense/Quota/Aliases.php"; }
');
    copy($root . '/src/opnsense/scripts/quota/aliases.php', $tmp . '/aliases.php');

    /* config.xml as OPNsense would hold the stand-ins' state, with $more beside it - a rule, say */
    function config_text($s, $more = '')
    {
        $aliases = '';
        foreach ($s['aliases'] ?? [] as $uuid => $a) {
            $aliases .= sprintf('<alias uuid="%s"><enabled>%s</enabled><name>%s</name><type>%s</type><description>%s</description></alias>',
                $uuid, $a['enabled'] ?? '1', $a['name'] ?? '', $a['type'] ?? '', $a['description'] ?? '');
        }
        return '<?xml version="1.0"?>' . "\n" . '<opnsense><OPNsense><Quota version="1.0.0"><general><enabled>' .
            ($s['enabled'] ?? '0') . '</enabled><cut_added>' . ($s['cut_added'] ?? '') . '</cut_added></general></Quota>' .
            '<Firewall><Alias><aliases>' . $aliases . '</aliases></Alias></Firewall><XGS><general><cut_lists>' .
            ($s['cut_lists'] ?? '') . '</cut_lists></general></XGS></OPNsense>' . $more . '</opnsense>' . "\n";
    }

    function run_script($tmp, $state, $env, $args = '', $more = '')
    {
        $config = $tmp . '/config.xml';
        file_put_contents($config, config_text(json_decode((string)@file_get_contents($state), true) ?: [], $more));
        $prefix = 'QUOTA_CONFIG=' . escapeshellarg($config) . ' ';
        foreach ($env as $k => $v) {
            $prefix .= $k . '=' . escapeshellarg($v) . ' ';
        }
        $out = shell_exec($prefix . 'STATE=' . escapeshellarg($state) . ' ' . escapeshellarg(PHP_BINARY) .
            ' -d include_path=' . escapeshellarg($tmp) . ' ' . escapeshellarg($tmp . '/aliases.php') . ' ' . $args);
        return [json_decode((string)$out, true), json_decode((string)@file_get_contents($state), true)];
    }

    function ours_uuid($saved)
    {
        foreach ($saved['aliases'] ?? [] as $uuid => $a) {
            if (($a['name'] ?? '') === 'quota_over') {
                return $uuid;
            }
        }
        return null;
    }

    file_put_contents($state, json_encode(['enabled' => '1', 'cut_lists' => 'owner-1',
        'aliases' => ['owner-1' => ['enabled' => '1', 'name' => 'blocked', 'type' => 'host', 'description' => 'mine']]]));
    [$out, $saved] = run_script($tmp, $state, ['XGS' => '1']);
    $q = ours_uuid($saved);
    check(($out['status'] ?? '') === 'ok' && $q !== null && ($saved['saved'] ?? 0) === 1,
        'aliases.php, on: quota_over made, the owner\'s alias left, saved once');
    check(($saved['cut_lists'] ?? '') === 'owner-1,' . $q && ($saved['cut_added'] ?? '') === $q && ($out['cut']['listed'] ?? false),
        'aliases.php: the cut list holds it after the owner\'s entry, and the record says the plugin put it there');
    [$out, $saved] = run_script($tmp, $state, ['XGS' => '1']);
    check(($out['changes'] ?? null) === [] && ($saved['saved'] ?? 0) === 1, 'aliases.php again, nothing changed: nothing saved');
    $saved['cut_lists'] = 'owner-1';
    file_put_contents($state, json_encode($saved));
    [$out, $saved] = run_script($tmp, $state, ['XGS' => '1']);
    check(($saved['cut_lists'] ?? '') === 'owner-1' && ($out['changes'] ?? null) === [] && !($out['cut']['listed'] ?? true),
        'aliases.php after the owner took it out of the cut list: not put back, and said not listed');
    $saved['enabled'] = '0';
    file_put_contents($state, json_encode($saved));
    [$out, $saved] = run_script($tmp, $state, ['XGS' => '1']);
    check(($out['status'] ?? '') === 'ok' && ours_uuid($saved) === null && ($saved['cut_added'] ?? 'x') === '' &&
        ($saved['cut_lists'] ?? '') === 'owner-1', 'aliases.php, off: removed, the record forgets it');
    $saved['enabled'] = '1';
    file_put_contents($state, json_encode($saved));
    [$out, $saved] = run_script($tmp, $state, ['XGS' => '1']);
    $q = ours_uuid($saved);
    check(($saved['cut_lists'] ?? '') === 'owner-1,' . $q, 'on again: made again, and in the cut list again');
    $saved['enabled'] = '0';
    file_put_contents($state, json_encode($saved));
    [$out, $saved] = run_script($tmp, $state, ['XGS' => '1'], '', '<filter><rule><source><network>quota_over</network></source></rule></filter>');
    check(($saved['aliases'][$q]['enabled'] ?? '') === '0' && ($saved['cut_lists'] ?? '') === 'owner-1' &&
        ($out['status'] ?? '') === 'ok', 'aliases.php, off, a rule naming it: switched off, and out of the cut list');
    unset($saved['aliases'][$q]);
    $saved['enabled'] = '1';
    file_put_contents($state, json_encode($saved));
    $before = $saved;
    [$out, $after] = run_script($tmp, $state, ['XGS' => '1', 'REFUSE' => 'alias']);
    check(($out['status'] ?? '') === 'failed' && ($after['saved'] ?? 0) === ($before['saved'] ?? 0) && ours_uuid($after) === null,
        'aliases.php, the Alias model refusing: said, nothing saved');
    [$out, $after] = run_script($tmp, $state, []);
    $q = ours_uuid($after);
    check(($out['status'] ?? '') === 'ok' && $q !== null && ($out['cut']['xgs'] ?? true) === false &&
        ($after['cut_lists'] ?? '') === 'owner-1' && ($after['cut_added'] ?? '') === '',
        'aliases.php without os-xgs-npu: the alias made, no cut list or record touched');
    [$out, $after] = run_script($tmp, $state, ['XGS' => '1']);
    check(($after['cut_lists'] ?? '') === 'owner-1,' . $q && ($after['cut_added'] ?? '') === $q,
        'os-xgs-npu installed after the alias was made: put in the cut list once, and recorded');
    [$out, $after] = run_script($tmp, $state, ['XGS' => '1'], '--remove');
    check(($out['status'] ?? '') === 'ok' && ours_uuid($after) === null && ($after['cut_lists'] ?? '') === 'owner-1' &&
        ($after['cut_added'] ?? 'x') === '', 'aliases.php --remove: the alias out, out of the cut list and of the record');
    $after['aliases']['b1'] = ['enabled' => '1', 'name' => 'quota_over', 'type' => 'host', 'description' => 'my own'];
    $after['cut_lists'] = 'owner-1,b1';
    file_put_contents($state, json_encode($after));
    [$out, $last] = run_script($tmp, $state, ['XGS' => '1']);
    check(($out['status'] ?? '') === 'ok' && ($last['aliases']['b1']['type'] ?? '') === 'host' && ($last['cut_lists'] ?? '') ===
        'owner-1,b1' && count($out['notes'] ?? []) === 1, 'the owner\'s alias of that name: his, and his entry in the cut list, left');

    foreach (glob($tmp . '/script/*') as $f) {
        unlink($f);
    }
    rmdir($tmp . '/script');
    foreach (glob($tmp . '/*') as $f) {
        unlink($f);
    }
    rmdir($tmp);

    echo $failed ? "$failed of $checks checks failed\n" : "$checks checks passed\n";
    exit($failed ? 1 : 0);
}
