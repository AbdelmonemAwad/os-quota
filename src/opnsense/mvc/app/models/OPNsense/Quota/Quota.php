<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\Quota;

use OPNsense\Base\BaseModel;
use OPNsense\Base\Messages\Message;

class Quota extends BaseModel
{
    /* the longest a cycle can be, in minutes: a time quota longer than its cycle would never be reached */
    const CYCLE_MINUTES = ['day' => 1440, 'week' => 10080, 'month' => 44640];

    /**
     * Beside each field's own checks, for each quota row: its host one address or one MAC that can be a
     * device's (library Host), at least one limit - volume or minutes - and minutes no more than its cycle
     * holds. Each said on the field it is about, so the dialog shows it where it belongs.
     */
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);
        foreach ($this->quotas->quota->iterateItems() as $uuid => $row) {
            $at = 'quotas.quota.' . $uuid . '.';
            $host = trim((string)$row->host);
            if ($host !== '' && Host::parse($host) === null) {
                $messages->appendMessage(new Message(gettext('An IPv4 or IPv6 address, or a MAC address.'), $at . 'host'));
            }
            $volume = trim((string)$row->volume);
            $minutes = trim((string)$row->minutes);
            if ($volume === '' && $minutes === '') {
                $messages->appendMessage(new Message(gettext('Give a volume, minutes of use, or both.'), $at . 'volume'));
            }
            $longest = self::CYCLE_MINUTES[(string)$row->cycle] ?? null;
            if ($minutes !== '' && ctype_digit($minutes) && $longest !== null && (int)$minutes > $longest) {
                $messages->appendMessage(new Message(
                    sprintf(gettext('A cycle of this length holds %d minutes at most.'), $longest),
                    $at . 'minutes'
                ));
            }
        }
        return $messages;
    }
}
