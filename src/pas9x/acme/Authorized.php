<?php

namespace pas9x\acme;

use pas9x\acme\crypto\PrivateKey;
use pas9x\acme\crypto\Signer;
use pas9x\acme\entity\Account;
use pas9x\acme\entity\Authorization;
use pas9x\acme\entity\Challenge;
use pas9x\acme\entity\Order;
use pas9x\acme\http\HttpRequest;

class Authorized
{
    use SharedInternals;

    public function __construct(
        public readonly ACME $acme,
        public readonly string $accountEntityUrl,
        public PrivateKey $accountKey,
        public Signer $signer
    )
    {
        $this->getInternals($this->acme);
    }

    public function formatAuthorizedRequest(string $url, ?object $payload = null): object
    {
        $protected = new \stdClass;
        $protected->alg = $this->signer->alg();
        $protected->kid = $this->accountEntityUrl;
        $protected->nonce = $this->internals->getNonce();
        $protected->url = $url;

        $protected_b64 = Utils::b64_urlencode(Utils::jsonEncode($protected));
        $payload_b64 = is_null($payload) ? '' : Utils::b64_urlencode(Utils::jsonEncode($payload));

        $request = new \stdClass;
        $request->protected = $protected_b64;
        $request->payload = $payload_b64;
        $request->signature = Utils::b64_urlencode($this->signer->sign($protected_b64 . '.' . $payload_b64));

        return $request;
    }

    public function executeAuthorizedRequest(string $url, ?object $payload = null): void
    {
        $headers = ['Content-Type' => 'application/jose+json'];
        $jose = Utils::jsonEncode($this->formatAuthorizedRequest($url, $payload));
        $request = new HttpRequest($url, 'POST', $headers, $jose);
        $this->internals->httpRequest($request);
    }

    public function getRawEntity(string $entityUrl): object
    {
        $this->executeAuthorizedRequest($entityUrl);
        $entity = $this->internals->parseResponse(true);
        return $entity;
    }

    public function getAccount(string $entityUrl): Account
    {
        $rawEntity = $this->getRawEntity($entityUrl);
        $account = new Account($entityUrl, $rawEntity, $this);
        return $account;
    }

    public function getOrder(string $entityUrl): Order
    {
        $rawEntity = $this->getRawEntity($entityUrl);
        $order = new Order($entityUrl, $rawEntity, $this);
        return $order;
    }

    public function getAuthorization(string $entityUrl): Authorization
    {
        $rawEntity = $this->getRawEntity($entityUrl);
        $authorization = new Authorization($entityUrl, $rawEntity, $this);
        return $authorization;
    }

    public function getChallenge(string $entityUrl): Challenge
    {
        $rawEntity = $this->getRawEntity($entityUrl);
        $challenge = new Challenge($entityUrl, $rawEntity, $this);
        return $challenge;
    }
}