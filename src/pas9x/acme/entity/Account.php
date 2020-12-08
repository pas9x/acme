<?php

namespace pas9x\acme\entity;

use InvalidArgumentException;
use pas9x\acme\ACME;
use pas9x\acme\contracts\PrivateKey;
use pas9x\acme\contracts\Signer;
use pas9x\acme\dto\OrderIdentifier;
use pas9x\acme\implementations\crypto\RSAPrivateKey;
use pas9x\acme\implementations\crypto\RSAPrivateKeyGenerator;
use pas9x\acme\implementations\crypto\RSASigner;
use pas9x\acme\Utils;

class Account extends Entity
{
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

    /** @var ACME $acme */
    private $acme;

    /** @var Account_internals $internals */
    protected $internals;

    /** @var PrivateKey $accountKey */
    protected $accountKey;

    /** @var Signer $signer */
    protected $accountSigner = null;

    public function __construct(string $entityUrl, array $rawEntity, ACME $acme, PrivateKey $accountKey, Signer $accountSigner = null)
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
        $order->primaryDomain($payload['identifiers'][0]['value']);
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

    public function revokeCert(string $certificatePem, int $reason = self::REVOCATION_REASON_UNSPECIFIED)
    {
        if (!in_array($reason, static::REVOCATION_REASONS)) {
            throw new InvalidArgumentException('Invalid revocation reason: ' . $reason);
        }
        $url = $this->acme()->internals()->directoryItem('revokeCert');
        $payload = [
            'certificate' => Utils::b64_urlencode(Utils::pemToDer($certificatePem)),
            'reason' => $reason,
        ];
        $this->internals()->joseRequest($url, $payload);
        $this->acme()->internals()->parseResponse(false);
    }

    public function keyChange(PrivateKey $newKey = null, Signer $newSigner = null)
    {
        if ($newKey === null) {
            $generator = new RSAPrivateKeyGenerator(4096);
            /** @var RSAPrivateKey $newKey */
            $newKey = $generator->generatePrivateKey();
            $newSigner = new RSASigner($newKey, RSASigner::ALG_RS256);
        } else {
            if ($newSigner === null) {
                $newSigner = Utils::autodetectSigner($newKey);
            }
        }
        $newPublicKey = $newKey->getPublicKey();

        $url = $this->acme()->internals()->directoryItem('keyChange');

        $subprotected = [
            'alg' => $newSigner->alg(),
            'jwk' => $newPublicKey->getJWK(),
            'url' => $url,
        ];
        $subprotected_b64 = Utils::b64_urlencode(Utils::jsonEncode($subprotected));

        $subpayload = [
            'account' => $this->url(),
            'oldKey' => $this->accountKey()->getPublicKey()->getJWK(),
        ];
        $subpayload_b64 = Utils::b64_urlencode(Utils::jsonEncode($subpayload));

        $payload = [
            'protected' => $subprotected_b64,
            'payload' => $subpayload_b64,
            'signature' => Utils::b64_urlencode($newSigner->sign($subprotected_b64 . '.' . $subpayload_b64)),
        ];

        $this->internals()->joseRequest($url, $payload);
        $this->acme()->internals()->parseResponse(false);
        $this->accountKey($newKey);
        $this->accountSigner($newSigner);
    }

    public function update(array $fields)
    {
        $this->internals()->joseRequest($this->url(), $fields);
        $this->acme()->internals()->parseResponse(false);
    }

    /**
     * @param string[] $contacts
     */
    public function updateContacts(array $contacts)
    {
        $this->update(['contact' => $contacts]);
    }

    public function deactivate()
    {
        $this->update(['status' => 'deactivated']);
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