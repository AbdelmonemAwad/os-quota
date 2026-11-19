<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * What a quota's Host may be (settled point 9's starred choice): one address, IPv4 or IPv6, or a MAC,
 * whose addresses the scripts follow through OPNsense's host discovery at each read, so a device with
 * IPv4 and IPv6 keeps one quota while its IPv6 addresses change. Not a network: a quota is one host's.
 *
 * Refused, as scripts/quota/settings.py's host() refuses them: an address that is unspecified,
 * loopback, link-local, multicast or the IPv4 broadcast, and a MAC that is all zeros, the broadcast or a
 * multicast one - none of them is one device's traffic through the firewall.
 */

namespace OPNsense\Quota;

class Host
{
    /**
     * ['address', the address] or ['mac', the MAC in lower case with colons - 02:00:00:aa:bb:cc] for a host a
     * quota may name; null otherwise.
     */
    public static function parse($text)
    {
        $text = strtolower(trim((string)$text));
        if (preg_match('/^[0-9a-f]{2}([:-]?)[0-9a-f]{2}(\1[0-9a-f]{2}){4}$/', $text)) {
            $digits = preg_replace('/[:-]/', '', $text);
            $mac = implode(':', str_split($digits, 2));
            if ($mac === '00:00:00:00:00:00' || $mac === 'ff:ff:ff:ff:ff:ff' || (hexdec(substr($digits, 0, 2)) & 1)) {
                return null;
            }
            return ['mac', $mac];
        }
        if (filter_var($text, FILTER_VALIDATE_IP) === false) {
            return null;
        }
        $packed = inet_pton($text);
        if ($packed === false) {
            return null;
        }
        if (strlen($packed) === 4) {
            $first = ord($packed[0]);
            if ($text === '255.255.255.255' || $first === 0 || $first === 127 || ($first >= 224 && $first <= 239) ||
                strncmp($packed, "\xa9\xfe", 2) === 0) {
                return null;
            }
        } else {
            $first = ord($packed[0]);
            $second = ord($packed[1]);
            if ($packed === str_repeat("\0", 16) || $packed === str_repeat("\0", 15) . "\1" || $first === 0xff ||
                ($first === 0xfe && ($second & 0xc0) === 0x80)) {
                return null;
            }
        }
        return ['address', inet_ntop($packed)];
    }
}
