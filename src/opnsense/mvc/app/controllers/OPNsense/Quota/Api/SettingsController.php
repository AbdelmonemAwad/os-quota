<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\Quota\Api;

use OPNsense\Base\ApiMutableModelControllerBase;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'quota';
    protected static $internalModelClass = '\OPNsense\Quota\Quota';

    /* the quota rows: a host each, by volume, by minutes of use, or both */

    public function searchQuotasAction()
    {
        return $this->searchBase('quotas.quota', ['enabled', 'host', 'volume', 'minutes', 'cycle', 'description'], 'host');
    }

    public function getQuotaAction($uuid = null)
    {
        return $this->getBase('quota', 'quotas.quota', $uuid);
    }

    public function addQuotaAction()
    {
        return $this->addBase('quota', 'quotas.quota');
    }

    public function setQuotaAction($uuid)
    {
        return $this->setBase('quota', 'quotas.quota', $uuid);
    }

    public function delQuotaAction($uuid)
    {
        return $this->delBase('quotas.quota', $uuid);
    }

    public function toggleQuotaAction($uuid, $enabled = null)
    {
        return $this->toggleBase('quotas.quota', $uuid, $enabled);
    }
}
