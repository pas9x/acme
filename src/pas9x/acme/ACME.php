<?php

namespace pas9x\acme;

use Exception;
use LogicException;
use pas9x\acme\dto\ExternalAccountBinding;
use pas9x\acme\implementations\crypto\RSAPrivateKey;
use pas9x\acme\implementations\crypto\RSASigner;
use pas9x\acme\implementations\http\curl\CurlClient;
use pas9x\acme\contracts\HttpClient;
use pas9x\acme\entity\Account;
use pas9x\acme\contracts\PrivateKey;
use pas9x\acme\contracts\Signer;
use pas9x\acme\implementations\crypto\RSAPrivateKeyGenerator;
use pas9x\acme\implementations\crypto\HMACSigner;

class ACME
{
    /** @var array */
    protected $directory = null;

    /**
     * ZeroSSL CA. No test server. External account binding required.
     * https://acme.zerossl.com/v2/DV90
     *
     * Buypass CA. No external account binding required.
     * Production server: https://api.buypass.com/acme/directory
     * Test server: https://api.test4.buypass.no/acme/directory
     *
     * Let's Encrypt production server: https://acme-v02.api.letsencrypt.org/directory
     * Let's Encrypt test server: https://acme-staging-v02.api.letsencrypt.org/directory
     *
     * @var string $directoryUrl
     */
    protected $directoryUrl = 'https://acme-v02.api.letsencrypt.org/directory';

    /** @var ACME_internals $internals */
    protected $internals = null;

    /** @var HttpClient $httpClient */
    protected $httpClient = null;

    public function internals(): ACME_internals
    {
        if ($this->internals === null) {
            $this->internals = new ACME_internals($this);
        }
        return $this->internals;
    }

    public function directoryUrl(string $newUrl = null): string
    {
        if ($newUrl !== null) {
            $this->directoryUrl = $newUrl;
        }
        return $this->directoryUrl;
    }

    public function directory(array $newDirectory = null): array
    {
        if ($newDirectory === null) {
            if ($this->directory === null) {
                $this->directory = $this->internals()->getDirectory($this->directoryUrl());
            }
        } else {
            $this->directory = $newDirectory;
        }
        return $this->directory;
    }

    public function httpClient(HttpClient $newClient = null): HttpClient
    {
        if ($newClient === null) {
            if ($this->httpClient === null) {
                $this->httpClient = new CurlClient;
                $this->httpClient->addWatcher($this->internals());
            }
        } else {
            $this->httpClient = $newClient;
        }
        return $this->httpClient;
    }

    public function addEventListener(EventListener $listener)
    {
        $this->internals()->eventListeners[] = $listener;
    }

    public function externalAccountRequired(): bool
    {
        return $this->internals()->directoryItem('externalAccountRequired', false);
    }

    public function registerNewAccount(
        bool $termsOfServiceAgreed,
        string $email = null,
        ExternalAccountBinding $eab = null,
        PrivateKey $accountPrivateKey = null,
        Signer $accountRequestSigner = null
    ): Account
    {
        if ($accountPrivateKey === null) {
            $keyGenerator = new RSAPrivateKeyGenerator(4096);
            /** @var RSAPrivateKey $accountPrivateKey */
            $accountPrivateKey = $keyGenerator->generatePrivateKey();
            if ($accountRequestSigner === null) {
                $accountRequestSigner = new RSASigner($accountPrivateKey, RSASigner::ALG_RS256);
            }
        }
        if ($accountRequestSigner === null) {
            $accountRequestSigner = Utils::autodetectSigner($accountPrivateKey);
        }

        $url = $this->internals()->directoryItem('newAccount');

        $protected = [
            'alg' => $accountRequestSigner->alg(),
            'jwk' => $accountPrivateKey->getPublicKey()->getJWK(),
            'nonce' => $this->internals()->getNonce(),
            'url' => $url,
        ];

        $payload = [
            'termsOfServiceAgreed' => $termsOfServiceAgreed,
            'contact' => [],
        ];
        if ($email !== null) {
            $protected['contact'][] = $email;
        }

        if ($eab !== null) {
            $eabSigner = $eab->signer();
            if ($eabSigner === null) {
                $eabSigner = new HMACSigner($eab->key(), HMACSigner::ALG_HS256);
            }
            $eabProtected = [
                'alg' => $eabSigner->alg(),
                'kid' => $eab->kid(),
                'url' => $url,
            ];
            $eabProtected_b64 = Utils::b64_urlencode(Utils::jsonEncode($eabProtected));
            $eabPayload_b64 = Utils::b64_urlencode($accountPrivateKey->getPublicKey()->thumbprint());
            $payload['externalAccountBinding'] = [
                'protected' => $eabProtected_b64,
                'payload' => $eabPayload_b64,
                'signature' => Utils::b64_urlencode($eabSigner->sign($eabProtected_b64 . '.' . $eabPayload_b64)),
            ];
        }

        $protected_b64 = Utils::b64_urlencode(Utils::jsonEncode($protected));
        $payload_b64 = Utils::b64_urlencode(Utils::jsonEncode($payload));
        $jose = [
            'protected' => $protected_b64,
            'payload' => $payload_b64,
            'signature' => Utils::b64_urlencode($accountRequestSigner->sign($protected_b64 . '.' . $payload_b64)),
        ];
        $this->internals()->joseRequest($url, $jose);
        $response = $this->internals()->parseResponse(true);
        $location = $this->internals()->responseHeader('Location', true);
        $result = new Account($location, $response, $this, $accountPrivateKey, $accountRequestSigner);
        return $result;
    }

    public function getExistingAccount(
        PrivateKey $accountPrivateKey,
        ?string $accountUrl,
        Signer $accountRequestSigner = null
    ): Account
    {
        if ($accountRequestSigner === null) {
            $accountRequestSigner = Utils::autodetectSigner($accountPrivateKey);
        }

        $protected = [
            'alg' => $accountRequestSigner->alg(),
            'nonce' => $this->internals()->getNonce(),
        ];

        if ($accountUrl === null) {
            $url = $this->internals()->directoryItem('newAccount');
            $protected['jwk'] = $accountPrivateKey->getPublicKey()->getJWK();
            $payload = [
                'onlyReturnExisting' => true,
            ];
            $payload_b64 = Utils::b64_urlencode(Utils::jsonEncode($payload));
        } else {
            $url = $accountUrl;
            $protected['kid'] = $accountUrl;
            $payload_b64 = '';
        }
        $protected['url'] = $url;


        $protected_b64 = Utils::b64_urlencode(Utils::jsonEncode($protected));
        $jose = [
            'protected' => $protected_b64,
            'payload' => $payload_b64,
            'signature' => Utils::b64_urlencode($accountRequestSigner->sign($protected_b64 . '.' . $payload_b64)),
        ];
        $this->internals()->joseRequest($url, $jose);
        $response = $this->internals()->parseResponse(true);
        if ($accountUrl === null) {
            $accountUrl = $this->internals()->responseHeader('Location', true);
        }
        $result = new Account($accountUrl, $response, $this, $accountPrivateKey, $accountRequestSigner);
        return $result;
    }
}