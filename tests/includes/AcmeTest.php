<?php

require_once __DIR__ . '/../includes/bootstrap.php';

use pas9x\acme\ACME;
use pas9x\acme\Utils;
use pas9x\acme\entity\Account;
use pas9x\acme\entity\Order;
use pas9x\acme\dto\ExternalAccountBinding;
use pas9x\acme\dto\Certificate;

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

            $httpClientLibrary = getConfig('httpClient', 'native');
            if ($httpClientLibrary === 'guzzle') {
                $acme->httpClient(new \GuzzleHttp\Client);
            } elseif ($httpClientLibrary === 'symfony') {
                $acme->httpClient(new \Symfony\Component\HttpClient\Psr18Client);
            } elseif ($httpClientLibrary !== 'native') {
                throw new Exception('Unknown httpClient library: ' . $httpClientLibrary);
            }

            $this->acme = $acme;
        }
        return $this->acme;
    }

    public function registerAccount(): Account
    {
        $this->log('registerAccount()...');
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
                Utils::filePutContents($accountFile, json_encode($accountInfo, JSON_PRETTY_PRINT));
            }
        }
        return $this->account;
    }

    public function newOrder(): Order
    {
        $this->log('newOrder()...');
        $domains = $this->caSettings['domains'];
        if (empty($domains)) {
            throw new Exception('No domains in CA settings');
        }
        $account = $this->getAccount(false);
        $order = $account->newOrder($domains);
        $this->log('OK');
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
                Utils::filePutContents($orderFile, json_encode($orderInfo, JSON_PRETTY_PRINT));
            }
        }
        return $this->order;
    }

    public function registerCertificate(): Certificate
    {
        $this->log('registerCertificate()...');
        $order = $this->getOrder(false);
        $result = $order->registerCertificate();
        $this->log('OK');
        return $result;
    }

    public function getCertificate(): Certificate
    {
        $certFile = __DIR__ . "/../{$this->ca}_cert.json";
        if (file_exists($certFile)) {
            $certInfo = Utils::jsonDecode(file_get_contents($certFile));
            return new Certificate($certInfo['certificate'], $certInfo['caChain']);
        }

        $order = $this->getOrder(false);
        $certUrl = $order->certificate();
        if ($certUrl === null) {
            $cert = $this->registerCertificate();
        } else {
            $cert = $order->downloadCertificate();
        }
        $certInfo = [
            'certificate' => $cert->certificate(),
            'caChain' => $cert->caCertificateChain(),
        ];
        Utils::filePutContents($certFile, json_encode($certInfo, JSON_PRETTY_PRINT));
        return $cert;
    }

    public function revokeCertificate()
    {
        $cert = $this->getCertificate();
        $this->getAccount(false)->revokeCert($cert->certificate());
        $certFile = __DIR__ . "/../{$this->ca}_cert.json";
        if (file_exists($certFile)) {
            unlink($certFile);
        }
    }

    public function keyChange()
    {
        $account = $this->getAccount(false);
        $account->keyChange();
        $accountFile = __DIR__ . "/../{$this->ca}_account.json";
        $accountInfo = [
            'url' => $this->account->url(),
            'privateKey' => $account->accountKey()->getPrivateKeyPem(),
            'raw' => $account->raw(),
        ];
        Utils::filePutContents($accountFile, json_encode($accountInfo, JSON_PRETTY_PRINT));
    }

    public function deactivate()
    {
        $account = $this->getAccount(false);
        $accountFile = __DIR__ . "/../{$this->ca}_account.json";
        $account->deactivate();
        if (file_exists($accountFile)) {
            unlink($accountFile);
        }
    }
}
