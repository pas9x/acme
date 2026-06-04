<?php

namespace pas9x\acme\entity;

use pas9x\acme\AuthorizedEntity;
use pas9x\acme\crypto\Certificate;
use pas9x\acme\crypto\PrivateKey;
use pas9x\acme\crypto\PrivateKeyEC;
use pas9x\acme\crypto\Signer;
use pas9x\acme\dto\OrderIdentifier;
use pas9x\acme\enums\ECKeyCurve;
use pas9x\acme\Utils;

class Account extends AuthorizedEntity
{
    const STATUS_VALID = 'valid';
    const STATUS_DEACTIVATED = 'deactivated'; // The account was closed at the client's request
    const STATUS_REVOKED = 'revoked'; // The account was closed at the server's initiative

    const REVOCATION_REASON_UNSPECIFIED = 0;
    const REVOCATION_REASON_KEY_COMPROMISE = 1;
    const REVOCATION_REASON_CA_COMPROMISE = 2;
    const REVOCATION_REASON_AFFILIATION_CHANGED = 3;
    const REVOCATION_REASON_SUPERSEDED = 4;
    const REVOCATION_REASON_CESSATION_OF_OPERATION = 5;
    const REVOCATION_REASON_CERTIFICATE_HOLD = 6;
    const REVOCATION_REASON_REMOVE_FROM_CRL = 8;
    const REVOCATION_REASON_PRIVILEGE_WITHDRAWN = 9;
    const REVOCATION_REASON_AA_COMPROMISE = 10;

    protected const REVOCATION_REASONS = [
        self::REVOCATION_REASON_UNSPECIFIED,
        self::REVOCATION_REASON_KEY_COMPROMISE,
        self::REVOCATION_REASON_CA_COMPROMISE,
        self::REVOCATION_REASON_AFFILIATION_CHANGED,
        self::REVOCATION_REASON_SUPERSEDED,
        self::REVOCATION_REASON_CESSATION_OF_OPERATION,
        self::REVOCATION_REASON_CERTIFICATE_HOLD,
        self::REVOCATION_REASON_REMOVE_FROM_CRL,
        self::REVOCATION_REASON_PRIVILEGE_WITHDRAWN,
        self::REVOCATION_REASON_AA_COMPROMISE,
    ];

    /** @var string[]|null */
    public ?array $contact = null;

    public ?bool $termsOfServiceAgreed = null;
    public ?string $orders = null;

    // TODO: implement orders list https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2.1

    protected function getRequiredAttributes(): array
    {
        return [
            // 'orders', // Can't require this field due to bug in the boulder https://github.com/letsencrypt/boulder/issues/3335
        ];
    }

    protected function setRawEntity(object $rawEntity): void
    {
        parent::setRawEntity($rawEntity);
        $this->termsOfServiceAgreed = $this->getAttribute('termsOfServiceAgreed');
        $this->contact = $this->getAttribute('contact');
        $this->orders = $this->getAttribute('orders');
    }

    /**
     * @param OrderIdentifier[]|string[] $identifiers
     * @param int $notBefore
     * @param int $notAfter
     * @return Order
     */
    public function newOrder(array $identifiers, int $notBefore = 0, int $notAfter = 0): Order
    {
        if (empty($identifiers)) {
            throw new \InvalidArgumentException('Empty $identifiers');
        }
        $payload = new \stdClass;
        $payload->identifiers = [];

        foreach ($identifiers as $index => $identifier) {
            if ($identifier instanceof OrderIdentifier) {
                $payload->identifiers[] = (object)[
                    'type' => $identifier->type,
                    'value' => $identifier->value,
                ];
            } elseif (is_string($identifier)) {
                $payload->identifiers[] = (object)[
                    'type' => OrderIdentifier::TYPE_DNS,
                    'value' => $identifier,
                ];
            } else {
                throw new \InvalidArgumentException("Invalid type of \$identifiers[$index]: " . Utils::gettype($identifier));
            }
        }
        if ($notBefore !== 0) {
            $payload->notBefore = gmdate(DATE_RFC3339, $notBefore);
        }
        if ($notAfter !== 0) {
            $payload->notAfter = gmdate(DATE_RFC3339, $notAfter);
        }

        $url = $this->internals->getDirectoryItem('newOrder');
        $this->authorized->executeAuthorizedRequest($url, $payload);
        $rawOrderEntity = $this->internals->parseResponse(true);
        $orderEntityUrl = $this->internals->responseHeader('Location', true);
        $order = new Order($orderEntityUrl, $rawOrderEntity, $this->authorized);
        return $order;
    }

    public function getOrder(string $entityUrl): Order
    {
        $rawEntity = $this->authorized->getRawEntity($entityUrl);
        $order = new Order($entityUrl, $rawEntity, $this->authorized);
        return $order;
    }

    public function getAuthorization(string $entityUrl): Authorization
    {
        $rawEntity = $this->authorized->getRawEntity($entityUrl);
        $authorization = new Authorization($entityUrl, $rawEntity, $this->authorized);
        return $authorization;
    }

    public function getChallenge(string $entityUrl): Challenge
    {
        $rawEntity = $this->authorized->getRawEntity($entityUrl);
        $challenge = new Challenge($entityUrl, $rawEntity, $this->authorized);
        return $challenge;
    }

    public function revokeCert(string|Certificate $certificate, int $reason = self::REVOCATION_REASON_UNSPECIFIED): void
    {
        if (is_string($certificate)) {
            $certificatePem = $certificate;
        } elseif ($certificate instanceof Certificate) {
            $certificatePem = $certificate->pem;
        } else {
            throw new \LogicException;
        }

        if (!in_array($reason, static::REVOCATION_REASONS)) {
            throw new \InvalidArgumentException('Invalid revocation reason: ' . $reason);
        }
        $url = $this->internals->getDirectoryItem('revokeCert');
        $payload = new \stdClass;
        $payload->certificate = Utils::b64_urlencode(Utils::pemToDer($certificatePem));
        $payload->reason = $reason;
        $this->authorized->executeAuthorizedRequest($url, $payload);
        $this->internals->parseResponse(false);
    }

    public function getAccountKey(): PrivateKey
    {
        return $this->authorized->accountKey;
    }

    public function keyChange(?PrivateKey $newKey = null, ?Signer $newSigner = null): void
    {
        if ($newKey === null) {
            $newKey = PrivateKeyEC::generate(ECKeyCurve::P256);
            if ($newSigner !== null) {
                throw new \LogicException('Unable to use custom $newSigner without $newKey');
            }

        }
        if ($newSigner === null) {
            $newSigner = $newKey->getDefaultSigner();
        }

        $newPublicKey = $newKey->getPublicKey();

        $url = $this->internals->getDirectoryItem('keyChange');

        $subprotected = new \stdClass;
        $subprotected->alg = $newSigner->alg();
        $subprotected->jwk = $newPublicKey->getJwk();
        $subprotected->url = $url;
        $subprotected_b64 = Utils::b64_urlencode(Utils::jsonEncode($subprotected));

        $subpayload = new \stdClass;
        $subpayload->account = $this->getEntityUrl();
        $subpayload->oldKey = $this->authorized->accountKey->getPublicKey()->getJwk();
        $subpayload_b64 = Utils::b64_urlencode(Utils::jsonEncode($subpayload));

        $payload = new \stdClass;
        $payload->protected = $subprotected_b64;
        $payload->payload = $subpayload_b64;
        $payload->signature = Utils::b64_urlencode($newSigner->sign($subprotected_b64 . '.' . $subpayload_b64));

        $this->authorized->executeAuthorizedRequest($url, $payload);
        $this->internals->parseResponse(false);
        $this->authorized->accountKey = $newKey;
        $this->authorized->signer = $newSigner;
    }

    public function saveAccountFields(object $fields): void
    {
        $this->authorized->executeAuthorizedRequest($this->getEntityUrl(), $fields);
        $this->internals->parseResponse(false);
    }

    /**
     * @param string[] $contacts
     */
    public function saveAccountContacts(array $contacts)
    {
        $this->saveAccountFields((object)['contact' => $contacts]);
    }

    public function deactivate(): void
    {
        $this->saveAccountFields((object)['status' => 'deactivated']);
    }
}