<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\Quota\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Quota\Quota;

class ServiceController extends ApiControllerBase
{
    private function json($action, $params = null)
    {
        $backend = new Backend();
        $text = $params === null ? $backend->configdRun('quota ' . $action) :
            $backend->configdpRun('quota ' . $action, $params);
        $result = json_decode((string)$text, true);
        return is_array($result) ? $result : ['status' => 'failed', 'error' => gettext('No answer could be read.')];
    }

    /**
     * the cards, and each quota's use this cycle for the Quotas tab
     */
    public function statusAction()
    {
        return $this->json('status');
    }

    /**
     * The settings saved put into the firewall, in this order. On: the alias made (and put in XGS:
     * Settings' cut list where os-xgs-npu is installed), the filter reloaded so its block rules and its
     * table are pf's, then one read, so the counts and the table are right now and not at the next minute.
     * Off: the table emptied and the counting paused while the alias is there, the alias taken out - or
     * switched off where a rule or a setting still names it - the filter reloaded without the rules, and
     * the table taken out of pf once its alias is gone. When the alias could not be written nothing more is
     * done; off, the table is emptied all the same: off means nothing is blocked.
     */
    public function reconfigureAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $backend = new Backend();
        $on = $this->enabled();
        if (!$on) {
            $backend->configdRun('quota flush');
        }
        $result = $this->json('apply');
        if (($result['status'] ?? '') !== 'ok') {
            $result['enabled'] = $on;
            return $result;
        }
        $backend->configdRun('filter reload skip_alias');
        if ($on) {
            $result['account'] = $this->json('account');
        } else {
            $result['gone'] = $this->json('gone');
        }
        $result['enabled'] = $on;
        return $result;
    }

    /**
     * One quota's count of this cycle back to nothing - or every quota's, for 'all' - and a read at once,
     * so a host over it passes again now.
     */
    public function resetAction($uuid = null)
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $uuid = (string)$uuid;
        if ($uuid !== 'all' && !preg_match('/^[0-9a-fA-F-]{36}$/', $uuid)) {
            return ['status' => 'failed', 'error' => gettext('No such quota.')];
        }
        return $this->json('reset', [$uuid]);
    }

    /**
     * whether Quotas is on in the settings just saved
     */
    private function enabled()
    {
        return (string)(new Quota())->general->enabled === '1';
    }
}
