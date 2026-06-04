<?php

namespace pas9x\acme;

use pas9x\acme\crypto\PrivateKey;
use pas9x\acme\crypto\PrivateKeyEC;
use pas9x\acme\crypto\Signer;
use pas9x\acme\crypto\SignerHMAC;
use pas9x\acme\enums\ECKeyCurve;
use pas9x\acme\enums\SignatureAlgorithm;
use pas9x\acme\http\Client;
use pas9x\acme\dto\ExternalAccountBinding;
use pas9x\acme\entity\Account;

class ACME
{
    public const DEFAULT_DIRECTORY_URL = 'https://acme-v02.api.letsencrypt.org/directory';

    public readonly Client $httpClient;
    protected readonly ACME_internals $internals;
    protected ?object $directory = null;

    public function __construct(protected string $directoryUrl = self::DEFAULT_DIRECTORY_URL)
    {
        $this->httpClient = new Client;
        $this->internals = new ACME_internals($this);
    }

    public function getDirectoryUrl(): string
    {
        return $this->directoryUrl;
    }

    /**
     * ZeroSSL CA. No test server. External account binding required.
     * https://acme.zerossl.com/v2/DV90
     *
     * Buypass CA. No external account binding required.
     * DEPRECATED: https://github.com/acmesh-official/acme.sh/issues/6480
     * Production server: https://api.buypass.com/acme/directory
     * Test server: https://api.test4.buypass.no/acme/directory
     *
     * Let's Encrypt production server: https://acme-v02.api.letsencrypt.org/directory
     * Let's Encrypt test server: https://acme-staging-v02.api.letsencrypt.org/directory
     *
     * TODO: add support:
     *     Google Trust Services    https://pki.goog/
     *     SSL.com
     *
     * @var string $directoryUrl
     * @return void
     */
    public function setDirectoryUrl(string $directoryUrl): void
    {
        $this->directoryUrl = $directoryUrl;
        $this->directory = null;
    }

    public function getDirectory(bool $useCache = true): object
    {
        if ($this->directory === null || $useCache) {
            $this->directory = $this->internals->getDirectory($this->getDirectoryUrl());
        }
        return $this->directory;
    }

    public function setDirectory(object $directory): void
    {
        $this->directory = $directory;
    }

    public function getNonceLifetime(): int
    {
        return $this->internals->nonceLifetime;
    }

    public function setNonceLifetime(int $nonceLifetime): void
    {
        $this->internals->nonceLifetime = $nonceLifetime;
        $this->internals->lastNonce = 0;
    }

    public function isExternalAccountRequired(): bool
    {
        return $this->internals->getDirectoryItem('externalAccountRequired', false);
    }

    public function registerNewAccount (
        bool $termsOfServiceAgreed,
        ?string $email = null,
        ?ExternalAccountBinding $eab = null,
        ?PrivateKey $accountPrivateKey = null,
        ?Signer $accountRequestSigner = null
    ): Account
    {
        if ($accountPrivateKey === null) {
            $accountPrivateKey = PrivateKeyEC::generate(ECKeyCurve::P256);
            //$accountPrivateKey = PrivateKeyRSA::generate(4096);
            if ($accountRequestSigner !== null) {
                throw new \LogicException('Unable to use custom $accountRequestSigner with no $accountPrivateKey');
            }
        }
        if ($accountRequestSigner === null) {
            $accountRequestSigner = $accountPrivateKey->getDefaultSigner();
        }

        $url = $this->internals->getDirectoryItem('newAccount');

        $newaccProtected = new \stdClass;
        $newaccProtected->alg = $accountRequestSigner->alg();
        $newaccProtected->jwk = $accountPrivateKey->getPublicKey()->getJwk();
        $newaccProtected->nonce = $this->internals->getNonce();
        $newaccProtected->url = $url;

        $newaccPayload = new \stdClass;
        $newaccPayload->termsOfServiceAgreed = $termsOfServiceAgreed;
        $newaccPayload->contact = [];

        if ($email !== null) {
            $newaccPayload->contact[] = "mailto:$email";
        }

        if ($eab !== null) {
            $eabSigner = $eab->signer;
            if ($eabSigner === null) {
                $eabSigner = new SignerHMAC(SignatureAlgorithm::SHA256, $eab->key);
            }
            $eabProtected = new \stdClass;
            $eabProtected->alg = $eabSigner->alg();
            $eabProtected->kid = $eab->kid;
            $eabProtected->url = $url;

            $eabProtected_b64 = Utils::b64_urlencode(Utils::jsonEncode($eabProtected));
            $eabPayload_b64 = Utils::b64_urlencode($accountPrivateKey->getPublicKey()->getThumbprint());

            $eabJose = new \stdClass;
            $eabJose->protected = $eabProtected_b64;
            $eabJose->payload = $eabPayload_b64;
            $eabJose->signature = Utils::b64_urlencode($eabSigner->sign($eabProtected_b64 . '.' . $eabPayload_b64));

            $newaccPayload->externalAccountBinding = $eabJose;
        }

        $newaccProtected_b64 = Utils::b64_urlencode(Utils::jsonEncode($newaccProtected));
        $newaccPayload_b64 = Utils::b64_urlencode(Utils::jsonEncode($newaccPayload));
        $jewaccJose = new \stdClass;
        $jewaccJose->protected = $newaccProtected_b64;
        $jewaccJose->payload = $newaccPayload_b64;
        $jewaccJose->signature = Utils::b64_urlencode($accountRequestSigner->sign($newaccProtected_b64 . '.' . $newaccPayload_b64));

        $this->internals->joseRequest($url, $jewaccJose);
        $accountRawEntity = $this->internals->parseResponse(true);
        $accountEntityUrl = $this->internals->responseHeader('Location', true);

        $authorized = new Authorized($this, $accountEntityUrl, $accountPrivateKey, $accountRequestSigner);
        $result = new Account($accountEntityUrl, $accountRawEntity, $authorized);

        return $result;
    }

    public function getExistingAccount(
        PrivateKey $accountPrivateKey,
        ?string $accountEntityUrl,
        ?Signer $accountRequestSigner = null
    ): Account
    {
        if ($accountRequestSigner === null) {
            $accountRequestSigner = $accountPrivateKey->getDefaultSigner();
        }

        $getaccProtected = new \stdClass;
        $getaccProtected->alg = $accountRequestSigner->alg();
        $getaccProtected->nonce = $this->internals->getNonce();

        if ($accountEntityUrl === null) {
            $url = $this->internals->getDirectoryItem('newAccount');
            $getaccProtected->jwk = $accountPrivateKey->getPublicKey()->getJwk();
            $newaccPayload = new \stdClass;
            $newaccPayload->onlyReturnExisting = true;
            $payload_b64 = Utils::b64_urlencode(Utils::jsonEncode($newaccPayload));
        } else {
            $url = $accountEntityUrl;
            $getaccProtected->kid = $accountEntityUrl;
            $payload_b64 = '';
        }
        $getaccProtected->url = $url;

        $getaccProtected_b64 = Utils::b64_urlencode(Utils::jsonEncode($getaccProtected));
        $getaccJose = new \stdClass;
        $getaccJose->protected = $getaccProtected_b64;
        $getaccJose->payload = $payload_b64;
        $getaccJose->signature = Utils::b64_urlencode($accountRequestSigner->sign($getaccProtected_b64 . '.' . $payload_b64));

        $this->internals->joseRequest($url, $getaccJose);
        $accountRawEntity = $this->internals->parseResponse(true);
        if ($accountEntityUrl === null) {
            $accountEntityUrl = $this->internals->responseHeader('Location', true);
        }

        $authorized = new Authorized($this, $accountEntityUrl, $accountPrivateKey, $accountRequestSigner);
        $result = new Account($accountEntityUrl, $accountRawEntity, $authorized);

        return $result;
    }
}