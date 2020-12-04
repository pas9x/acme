<?php

namespace pas9x\acme\entity;

use InvalidArgumentException;
use pas9x\acme\ACME;
use pas9x\acme\contracts\PrivateKey;
use pas9x\acme\contracts\Signer;
use pas9x\acme\dto\OrderIdentifier;
use pas9x\acme\Utils;

class Account extends Entity
{
    /** @var ACME $acme */
    private $acme;

    /** @var Account_internals $internals */
    protected $internals;

    /** @var PrivateKey $accountKey */
    protected $accountKey;

    /** @var Signer $signer */
    protected $accountSigner = null;

    public function __construct($entityUrl, array $rawEntity, ACME $acme, PrivateKey $accountKey, Signer $accountSigner = null)
    {
        parent::__construct($entityUrl, $rawEntity);
        $this->acme = $acme;
        $this->internals = new Account_internals($this, $acme);
        $this->accountKey = $accountKey;
        if ($accountSigner === null) {
            $this->accountSigner = Utils::autodetectSigner($accountKey);
        }
    }

    public function acme(): ACME
    {
        return $this->acme;
    }

    public function internals(): Account_internals
    {
        return $this->internals;
    }

    public function accountKey(PrivateKey $newKey = null): PrivateKey
    {
        if ($newKey !== null) {
            $this->accountKey = $newKey;
        }
        return $this->accountKey;
    }

    public function accountSigner(Signer $newSigner = null): Signer
    {
        if ($newSigner === null) {
            if ($this->accountSigner === null) {
                $this->accountSigner = Utils::autodetectSigner($this->accountKey());
            }
        } else {
            $this->accountSigner = $newSigner;
        }
        return $this->accountSigner;
    }

    /**
     * @param OrderIdentifier[]|string[] $identifiers
     * @param int $notBefore
     * @param int $notAfter
     * @return Order
     */
    public function newOrder(array $identifiers, int $notBefore = null, int $notAfter = null): Order
    {
        if (empty($identifiers)) {
            throw new InvalidArgumentException('Empty $identifiers');
        }
        $payload = [
            'identifiers' => [],
        ];
        foreach ($identifiers as $index => $identifier) {
            if ($identifier instanceof OrderIdentifier) {
                $payload['identifiers'][] = [
                    'type' => $identifier->type(),
                    'value' => $identifier->value(),
                ];
            } elseif (is_string($identifier)) {
                $payload['identifiers'][] = [
                    'type' => OrderIdentifier::TYPE_DNS,
                    'value' => $identifier,
                ];
            } else {
                throw new InvalidArgumentException("Invalid type of \$identifiers[$index]: " . gettype($identifier));
            }
        }
        if ($notBefore !== null) {
            $payload['notBefore'] = gmdate(DATE_RFC3339, $notBefore);
        }
        if ($notAfter !== null) {
            $payload['notAfter'] = gmdate(DATE_RFC3339, $notAfter);
        }

        $url = $this->acme()->internals()->directoryItem('newOrder');
        $this->internals()->joseRequest($url, $payload);
        $rawOrderEntity = $this->acme()->internals()->parseResponse(true);
        $orderUrl = $this->acme()->internals()->responseHeader('Location', true);
        $order = new Order($orderUrl, $rawOrderEntity, $this);
        return $order;
    }

    public function getOrder(string $url): Order
    {
        $rawOrder = $this->internals()->getRawEntity($url);
        $order = new Order($url, $rawOrder, $this);
        return $order;
    }

    public function getAuthorization(string $url): Authorization
    {
        $rawAuthorization = $this->internals()->getRawEntity($url);
        $authorization = new Authorization($url, $rawAuthorization, $this);
        return $authorization;
    }

    public function getChallenge(string $url): Challenge
    {
        $rawChallenge = $this->internals()->getRawEntity($url);
        $challenge = new Challenge($url, $rawChallenge, $this);
        return $challenge;
    }

    public function refresh(array $rawEntity = null)
    {
        if ($rawEntity === null) {
            $rawEntity = $this->internals()->getRawEntity($this->url());
        }
        if ($this->construct) {
            $this->construct = false;
        } else {
            $this->setRawEntity($rawEntity);
        }
    }

    protected function requiredAttributes(): array
    {
        return [];
    }
}