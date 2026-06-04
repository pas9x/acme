<?php

namespace test;

use pas9x\acme\crypto\PrivateKey;
use pas9x\acme\crypto\PrivateKeyEC;
use pas9x\acme\crypto\PrivateKeyRSA;
use pas9x\acme\dto\ExternalAccountBinding;
use pas9x\acme\entity\Account;
use pas9x\acme\enums\KeyType;
use pas9x\acme\Utils;

trait AcmeTest_account
{
    private ?Account $account = null;

    public function getAccount(): Account
    {
        if ($this->account !== null) {
            return $this->account;
        }
        $this->account = $this->getExistingAccount();
        if (empty($this->account)) {
            $this->account = $this->registerNewAccount();
        }
        return $this->account;
    }

    protected function getAccountFile(): string {
        return BASEDIR . '/' . $this->ca->name . '_account_' . $this->accountKeyParams->__toString() . '.json';
    }

    public function registerNewAccount(): Account
    {
        if ($this->accountKeyParams->keyType === KeyType::RSA) {
            $accountKey = PrivateKeyRSA::generate($this->accountKeyParams->bits);
        } elseif ($this->accountKeyParams->keyType === KeyType::EC) {
            $accountKey = PrivateKeyEC::generate($this->accountKeyParams->curve);
        } else {
            throw new \LogicException('Unsupported key type: ' . $this->accountKeyParams->keyType->toString());
        }
        $accountFile = $this->getAccountFile();
        $account = $this->registerAccountForKey($accountKey);
        $this->writeAccount($accountFile, $account);
        return $account;
    }

    protected function registerAccountForKey(PrivateKey $key): Account
    {
        $details = $key->keyType->toString();
        if ($key->delegate instanceof PrivateKeyRSA) {
            $details .= ' ' . $key->delegate->bits;
        } elseif ($key->delegate instanceof PrivateKeyEC) {
            $details .= ' ' . $key->delegate->curve->toNistCode();
        }
        $this->log("registerAccountForKey($details)");

        $eab = null;
        if ($this->ca->externalAccountBinding !== null) {
            $eab = new ExternalAccountBinding(
                $this->ca->externalAccountBinding->kid,
                $this->ca->externalAccountBinding->key,
            );
        }

        $account = $this->getACME()->registerNewAccount(true, $this->ca->email, $eab, $key);
        $this->log('Refresh account...');
        $account->refresh();
        return $account;
    }

    protected function writeAccount(string $accountFile, Account $account)
    {
        $data = [
            'url' => $account->getEntityUrl(),
            'registration_date' => time(),
            'registration_date_str' => date('Y-m-d H:i:s'),
            'private_key' => $account->getAccountKey()->getPrivateKeyPem(),
        ];
        file_put_contents($accountFile, json_encode($data, JSON_PRETTY_PRINT));
    }

    protected function getExistingAccount(): ?Account
    {
        $accountFile = $this->getAccountFile();
        if (!is_file($accountFile)) {
            $this->log("Account file $accountFile not found");
            return null;
        }
        $json = file_get_contents($accountFile);
        $data = Utils::jsonDecode($json);
        $accountKey = new PrivateKey($data->private_key);
        $this->log("Using existing account $accountFile");
        $account = $this->getACME()->getExistingAccount($accountKey, $data->url);
        return $account;
    }
}