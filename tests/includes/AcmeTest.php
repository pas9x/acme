<?php

require_once __DIR__ . '/../includes/bootstrap.php';

use pas9x\acme\ACME;
use pas9x\acme\Utils;
use pas9x\acme\entity\Account;
use pas9x\acme\entity\Order;
use pas9x\acme\entity\Authorization;
use pas9x\acme\entity\Challenge;
use pas9x\acme\dto\ExternalAccountBinding;

class AcmeTest
{
    /** @var string $ca */
    public $ca;

    /** @var array $caSettings */
    public $caSettings;

    /** @var callable $logger */
    public $logger;

    /** @var ACME $acme */
    public $acme = null;

    /** @var Account $account */
    public $account = null;

    /** @var Order $order */
    public $order = null;

    public function __construct(string $ca, callable $logger = null)
    {
        $this->ca = $ca;
        $this->caSettings = getConfig('ca.' . $ca);

        if ($logger === null) {
            $this->logger = function(string $msg) {
                stdout("[{$this->ca}] $msg\n");
            };
        } else {
            $this->logger = $logger;
        }
    }

    public function log(string $msg)
    {
        call_user_func($this->logger, $msg);
    }

    public function getAcme(): ACME
    {
        if ($this->acme === null) {
            $acme = new ACME;
            $acme->directoryUrl($this->caSettings['directoryUrl']);
            $this->acme = $acme;
        }
        return $this->acme;
    }

    public function registerAccount(): Account
    {
        $this->log('testRegisterAccount()...');
        $acme = $this->getAcme();

        if (isset($caSettings['externalAccountBinding'])) {
            $eab = new ExternalAccountBinding($this->caSettings['externalAccountBinding']['kid'], $this->caSettings['externalAccountBinding']['key']);
        } else {
            $eab = null;
        }

        $account = $acme->registerNewAccount(true, $this->caSettings['email'], $eab);

        $this->log('OK');
        return $account;
    }

    public function getAccount(bool $registerNew): Account
    {
        if ($this->account === null) {
            $accountFile = __DIR__ . "/../{$this->ca}_account.json";
            if (file_exists($accountFile) && !$registerNew) {
                $acme = $this->getAcme();
                $accountInfo = Utils::jsonDecode(file_get_contents($accountFile));
                $accountKey = Utils::loadPrivateKey($accountInfo['privateKey']);
                $this->account = $acme->getExistingAccount($accountKey, $accountInfo['url']);
            } else {
                $this->account = $this->registerAccount();
                $accountInfo = [
                    'url' => $this->account->url(),
                    'privateKey' => $this->account->accountKey()->getPrivateKeyPem(),
                    'raw' => $this->account->raw(),
                ];
                file_put_contents($accountFile, json_encode($accountInfo, JSON_PRETTY_PRINT));
            }
        }
        return $this->account;
    }

    public function newOrder(): Order
    {
        $domains = $this->caSettings['domains'];
        if (empty($domains)) {
            throw new Exception('No domains in CA settings');
        }
        $account = $this->getAccount(false);
        $order = $account->newOrder($domains);
        return $order;
    }

    public function getOrder(bool $newOrder): Order
    {
        if ($this->order === null) {
            $orderFile = __DIR__ . "/../{$this->ca}_order.json";
            if (file_exists($orderFile) && !$newOrder) {
                $orderInfo = Utils::jsonDecode(file_get_contents($orderFile));
                $account = $this->getAccount(false);
                $this->order = $account->getOrder($orderInfo['url']);
            } else {
                $this->order = $this->newOrder();
                $orderInfo = [
                    'url' => $this->order->url(),
                    'raw' => $this->order->raw(),
                ];
                file_put_contents($orderFile, json_encode($orderInfo, JSON_PRETTY_PRINT));
            }
        }
        return $this->order;
    }
}
