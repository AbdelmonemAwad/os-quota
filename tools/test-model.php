<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The plugin's model (models/OPNsense/Quota/Quota.php) and what it checks a host with (library
 * OPNsense\Quota\Host), run as a Save runs them, with stand-ins for what they reach of OPNsense:
 * BaseModel, whose fields' own checks give nothing here, as for valid entries, and Message.
 *
 * What is checked: a host one address - IPv4 or IPv6, written as pf prints it - or one MAC, written
 * with colons, hyphens or neither; refused, an address that is unspecified, "this network", loopback,
 * link-local, multicast or the IPv4 broadcast, a MAC all zeros, the broadcast or multicast, a network,
 * a name; a row with neither volume nor minutes told on its volume; minutes past what its cycle holds
 * told on its minutes; each row told on its own fields; and the model's own XML in step - its
 * defaults (off, 100 KB) and its options - with scripts/quota/settings.py's.
 *
 *   php tools/test-model.php
 */

namespace OPNsense\Base\Messages {
    class Message
    {
        private $message;
        private $field;

        public function __construct($message, $field = '')
        {
            $this->message = $message;
            $this->field = $field;
        }

        public function getMessage()
        {
            return $this->message;
        }

        public function getField()
        {
            return $this->field;
        }
    }
}

namespace OPNsense\Base {
    class Messages implements \IteratorAggregate
    {
        public $all = [];

        public function appendMessage($message)
        {
            $this->all[] = $message;
        }

        public function getIterator(): \Iterator
        {
            return new \ArrayIterator($this->all);
        }
    }

    class Rows
    {
        private $rows;

        public function __construct($rows)
        {
            $this->rows = $rows;
        }

        public function iterateItems()
        {
            foreach ($this->rows as $uuid => $row) {
                yield $uuid => (object)$row;
            }
        }
    }

    abstract class BaseModel
    {
        public static $rows = [];
        public $quotas;

        public function __construct()
        {
            $this->quotas = (object)['quota' => new Rows(self::$rows)];
        }

        public function performValidation($validateFullModel = false)
        {
            return new Messages();
        }
    }
}

namespace {
    if (!function_exists('gettext')) {
        function gettext($text)
        {
            return $text;
        }
    }

    $root = dirname(__DIR__);
    require $root . '/src/opnsense/mvc/app/library/OPNsense/Quota/Host.php';
    require $root . '/src/opnsense/mvc/app/models/OPNsense/Quota/Quota.php';

    use OPNsense\Base\BaseModel;
    use OPNsense\Quota\Host;
    use OPNsense\Quota\Quota;

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

    /* [[field, message]] of a Save with these rows */
    function saved($rows)
    {
        BaseModel::$rows = $rows;
        $out = [];
        foreach ((new Quota())->performValidation() as $message) {
            $out[] = [$message->getField(), $message->getMessage()];
        }
        return $out;
    }

    function row($host, $volume = '1000', $minutes = '', $cycle = 'day')
    {
        return ['host' => $host, 'volume' => $volume, 'minutes' => $minutes, 'cycle' => $cycle];
    }

    $taken = [
        '192.0.2.10' => ['address', '192.0.2.10'],
        '2001:DB8:1::0010' => ['address', '2001:db8:1::10'],
        '198.51.100.255' => ['address', '198.51.100.255'],
        '02:00:00:AA:BB:CC' => ['mac', '02:00:00:aa:bb:cc'],
        '02-00-00-aa-bb-cc' => ['mac', '02:00:00:aa:bb:cc'],
        '020000aabbcc' => ['mac', '02:00:00:aa:bb:cc'],
        ' de:ad:be:ef:00:01 ' => ['mac', 'de:ad:be:ef:00:01'],
    ];
    foreach ($taken as $text => $want) {
        check(Host::parse($text) === $want, "a host: \"$text\" taken as " . implode(' ', $want));
    }
    foreach (['0.0.0.0', '0.1.2.3', '127.0.0.1', '169.254.10.1', '224.0.0.251', '239.1.1.1', '255.255.255.255', '::', '::1',
              'fe80::1', 'febf::1', 'ff02::1', '00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff', '01:00:5e:00:00:fb', '33:33:00:00:00:01',
              '192.0.2.0/24', '2001:db8::/64', 'host.example', '02:00:00:aa:bb', '02:00:00:aa-bb:cc', ''] as $text) {
        check(Host::parse($text) === null, "not a host: \"$text\"");
    }

    check(saved(['u1' => row('192.0.2.10'), 'u2' => row('02:00:00:aa:bb:cc', '', '120')]) === [],
        'a quota by volume on an address and one by time on a MAC: taken');
    check(saved(['u1' => row('192.0.2.0/24')]) === [['quotas.quota.u1.host', 'An IPv4 or IPv6 address, or a MAC address.']],
        'a network: refused on the host');
    check(saved(['u1' => row('192.0.2.10', '', '')]) === [['quotas.quota.u1.volume', 'Give a volume, minutes of use, or both.']],
        'neither volume nor minutes: told on the volume');
    check(saved(['u1' => row('192.0.2.10', '', '1441', 'day'), 'u2' => row('192.0.2.11', '', '10081', 'week'),
                 'u3' => row('192.0.2.12', '', '44640', 'month'), 'u4' => row('192.0.2.13', '', '1440', 'day')]) ===
        [['quotas.quota.u1.minutes', 'A cycle of this length holds 1440 minutes at most.'],
         ['quotas.quota.u2.minutes', 'A cycle of this length holds 10080 minutes at most.']],
        'minutes past what the cycle holds: told on the minutes of those rows alone');
    check(saved(['u1' => row('host.example', '', '')]) ===
        [['quotas.quota.u1.host', 'An IPv4 or IPv6 address, or a MAC address.'],
         ['quotas.quota.u1.volume', 'Give a volume, minutes of use, or both.']], 'two faults of one row: both told');
    check(saved(['u1' => row('', '1')]) === [], 'an empty host: the field\'s own Required says it, not said twice');

    /* the model's XML and the scripts' reading of it - read as text: not every PHP the checks run on has
       SimpleXML */
    $xml = file_get_contents($root . '/src/opnsense/mvc/app/models/OPNsense/Quota/Quota.xml');
    $settings = file_get_contents($root . '/src/opnsense/scripts/quota/settings.py');
    function element($xml, $path)
    {
        foreach (explode('/', $path) as $tag) {
            if (!preg_match('#<' . $tag . '\b[^>]*>(.*?)</' . $tag . '>#s', $xml, $m)) {
                return null;
            }
            $xml = $m[1];
        }
        return trim($xml);
    }
    check(element($xml, 'general/enabled/Default') === '0', 'the model: off by default');
    $form = file_get_contents($root . '/src/opnsense/mvc/app/controllers/OPNsense/Quota/forms/general.xml');
    check(element($xml, 'general/minute_threshold/Default') === null &&
        element($xml, 'general/minute_threshold/Required') === 'N' && strpos($settings, 'MINUTE_KB = 100') !== false &&
        strpos($form, "Empty: the plugin's own value, 100 KB in this release") !== false,
        "the minute threshold: empty by default - no default saved into config.xml, where a later release's " .
        "could not reach it - and empty is settings.py's provisional 100 KB, which the help names");
    preg_match_all('#<(\w+)>[^<]*</\1>#', (string)element($xml, 'quotas/quota/cycle/OptionValues'), $found);
    $options = $found[1];
    check($options === ['day', 'week', 'month'] && strpos($settings, "CYCLES = ('day', 'week', 'month')") !== false &&
        array_keys(Quota::CYCLE_MINUTES) === $options, 'the cycles: the same three in the model, its check and settings.py');
    check(element($xml, 'quotas/quota/minutes/MaximumValue') === '44640' && Quota::CYCLE_MINUTES['month'] === 44640,
        'the longest time quota is a month of 31 days');
    $mask = element($xml, 'quotas/quota/host/Mask');
    $through = true;
    foreach (array_keys($taken) as $text) {
        $through = $through && preg_match($mask, trim($text)) === 1;
    }
    check($through, 'every host Host takes passes the field\'s own mask first');

    echo $failed ? "$failed of $checks checks failed\n" : "$checks checks passed\n";
    exit($failed ? 1 : 0);
}
