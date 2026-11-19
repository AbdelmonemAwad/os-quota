<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The page's API (Api/ServiceController and Api/SettingsController) and its index, run as OPNsense runs
 * them, with stand-ins for what they reach of OPNsense's MVC: ApiControllerBase and
 * ApiMutableModelControllerBase - the request, the grid's search, the rows' add and set, which here hand
 * back what they were given - IndexController's forms and view, configd (Backend) and the plugin's model.
 *
 * What is checked: the status script's answer passed on, and one that cannot be read said; Apply in its
 * order - on: the alias, the filter, a read; off: the table emptied first, the alias, the filter, the table
 * taken out of pf - and nothing more when the alias could not be written; nothing for a GET; Reset of one
 * quota or all, the id passed to configd quoted, a GET or an id that is none refused; the quota rows'
 * grid, dialog and toggle on the model's path; the page's forms.
 *
 *   php tools/test-mvc.php
 */

namespace OPNsense\Base {
    class Request
    {
        public $post = true;

        public function isPost()
        {
            return $this->post;
        }
    }

    class ApiControllerBase
    {
        public $request;

        public function __construct()
        {
            $this->request = new Request();
        }
    }

    class ApiMutableModelControllerBase extends ApiControllerBase
    {
        public function searchBase($path, $fields = null, $sort = null)
        {
            return ['search', $path, $fields, $sort];
        }

        public function getBase($key, $path, $uuid = null)
        {
            return ['get', $key, $path, $uuid];
        }

        public function addBase($post, $path, $overlay = null)
        {
            return ['add', $post, $path, $overlay];
        }

        public function setBase($post, $path, $uuid, $overlay = null)
        {
            return ['set', $post, $path, $uuid, $overlay];
        }

        public function delBase($path, $uuid)
        {
            return ['del', $path, $uuid];
        }

        public function toggleBase($path, $uuid, $enabled = null)
        {
            return ['toggle', $path, $uuid, $enabled];
        }
    }

    class IndexController
    {
        public $view;

        public function __construct()
        {
            $this->view = new class {
                public $picked;

                public function pick($name)
                {
                    $this->picked = $name;
                }
            };
        }

        protected function getForm($name)
        {
            return 'form:' . $name;
        }
    }
}

namespace OPNsense\Core {
    class Backend
    {
        public static $answers = [];
        public static $asked = [];

        public function configdRun($event, $detach = false)
        {
            self::$asked[] = $event;
            return self::$answers[$event] ?? null;
        }

        public function configdpRun($event, $params = [], $detach = false)
        {
            foreach ($params as $param) {
                $event .= ' ' . escapeshellarg($param);
            }
            return $this->configdRun($event, $detach);
        }
    }
}

namespace OPNsense\Quota {
    class Quota
    {
        public static $enabled = '1';
        public $general;

        public function __construct()
        {
            $this->general = (object)['enabled' => self::$enabled];
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
    require $root . '/src/opnsense/mvc/app/controllers/OPNsense/Quota/Api/ServiceController.php';
    require $root . '/src/opnsense/mvc/app/controllers/OPNsense/Quota/Api/SettingsController.php';
    require $root . '/src/opnsense/mvc/app/controllers/OPNsense/Quota/IndexController.php';

    use OPNsense\Core\Backend;
    use OPNsense\Quota\Api\ServiceController;
    use OPNsense\Quota\Api\SettingsController;
    use OPNsense\Quota\IndexController;
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

    function ask($answers = [])
    {
        Backend::$answers = $answers;
        Backend::$asked = [];
    }

    $ok = json_encode(['status' => 'ok', 'changes' => ['quota_over: added']]);

    /* the status */
    ask(['quota status' => json_encode(['enabled' => true, 'quotas' => []])]);
    check((new ServiceController())->statusAction() === ['enabled' => true, 'quotas' => []], 'status: the script\'s answer passed on');
    ask(['quota status' => 'not json']);
    check(((new ServiceController())->statusAction()['error'] ?? '') === 'No answer could be read.', 'status unreadable: said');

    /* Apply */
    Quota::$enabled = '1';
    ask(['quota apply' => $ok, 'quota account' => json_encode(['status' => 'ok', 'over' => 1])]);
    $got = (new ServiceController())->reconfigureAction();
    check(Backend::$asked === ['quota apply', 'filter reload skip_alias', 'quota account'],
        'Apply, on: the alias, the filter, then one read');
    check($got['status'] === 'ok' && $got['enabled'] === true && $got['account'] === ['status' => 'ok', 'over' => 1] &&
        $got['changes'] === ['quota_over: added'], 'Apply, on: what changed and the read\'s answer');
    Quota::$enabled = '0';
    ask(['quota apply' => json_encode(['status' => 'ok', 'changes' => ['quota_over: removed']]),
        'quota gone' => json_encode(['status' => 'ok', 'killed' => true])]);
    $got = (new ServiceController())->reconfigureAction();
    check(Backend::$asked === ['quota flush', 'quota apply', 'filter reload skip_alias', 'quota gone'],
        'Apply, off: the table emptied while its alias is there, the alias, the filter, the table taken out of pf');
    check($got['enabled'] === false && $got['gone'] === ['status' => 'ok', 'killed' => true], 'Apply, off: said');
    ask(['quota apply' => json_encode(['status' => 'failed', 'errors' => ['refused']])]);
    $got = (new ServiceController())->reconfigureAction();
    check(Backend::$asked === ['quota flush', 'quota apply'] && $got['status'] === 'failed' && $got['errors'] === ['refused'],
        'Apply, off, the alias not written: the table emptied all the same, nothing more done, the refusal said');
    Quota::$enabled = '1';
    ask(['quota apply' => null]);
    $got = (new ServiceController())->reconfigureAction();
    check(Backend::$asked === ['quota apply'] && $got['status'] === 'failed', 'Apply, no answer from the alias: nothing more done');
    $get = new ServiceController();
    $get->request->post = false;
    ask();
    check($get->reconfigureAction() === ['status' => 'failed'] && Backend::$asked === [], 'Apply by GET: nothing done');

    /* Reset */
    $uuid = '11111111-1111-4111-8111-111111111111';
    ask(["quota reset '$uuid'" => json_encode(['status' => 'ok', 'reset' => [$uuid]])]);
    $got = (new ServiceController())->resetAction($uuid);
    check(Backend::$asked === ["quota reset '$uuid'"] && $got['reset'] === [$uuid], 'Reset: the quota\'s id passed quoted, the answer back');
    ask(["quota reset 'all'" => json_encode(['status' => 'ok', 'reset' => [$uuid]])]);
    check(((new ServiceController())->resetAction('all')['status'] ?? '') === 'ok', 'Reset all');
    foreach (['', 'x; reboot', '../../etc', str_repeat('a', 37)] as $bad) {
        ask();
        $got = (new ServiceController())->resetAction($bad);
        check($got['status'] === 'failed' && Backend::$asked === [], 'Reset of "' . $bad . '": refused, configd not asked');
    }
    ask();
    check($get->resetAction($uuid) === ['status' => 'failed'] && Backend::$asked === [], 'Reset by GET: nothing done');

    /* the rows */
    $settings = new SettingsController();
    check($settings->searchQuotasAction() === ['search', 'quotas.quota', ['enabled', 'host', 'volume', 'minutes', 'cycle',
        'description'], 'host'], 'the grid: the rows\' fields, sorted by host');
    check($settings->getQuotaAction('u1') === ['get', 'quota', 'quotas.quota', 'u1'] &&
        $settings->addQuotaAction() === ['add', 'quota', 'quotas.quota', null] &&
        $settings->setQuotaAction('u1') === ['set', 'quota', 'quotas.quota', 'u1', null] &&
        $settings->delQuotaAction('u1') === ['del', 'quotas.quota', 'u1'] &&
        $settings->toggleQuotaAction('u1', '0') === ['toggle', 'quotas.quota', 'u1', '0'],
        'the dialog: get, add, set, del and toggle on quotas.quota, posted as "quota"');

    /* the page */
    $index = new IndexController();
    $index->indexAction();
    check($index->view->generalForm === 'form:general' && $index->view->formDialogQuota === 'form:dialogQuota' &&
        $index->view->picked === 'OPNsense/Quota/index', 'the page: its two forms and its view');

    echo $failed ? "$failed of $checks checks failed\n" : "$checks checks passed\n";
    exit($failed ? 1 : 0);
}
