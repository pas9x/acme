<?php

namespace pas9x\acme\entity;

use pas9x\acme\ACME;
use pas9x\acme\Utils;

/**
 * @internal
 */
class Account_internals
{
    /** @var Account $account */
    public $account;

    /** @var ACME $acme */
    public $acme;

    public function __construct(Account $account, ACME $acme)
    {
        $this->account = $account;
        $this->acme = $acme;
    }

    /**
     * @param string $url
     * @param array|object|null $payload
     * @return array
     */
    public function formatRequest(string $url, $payload = null): array
    {
        $signer = $this->account->accountSigner();
        $protected = [
            'alg' => $signer->alg(),
            'kid' => $this->account->url(),
            'nonce' => $this->acme->internals()->getNonce(),
            'url' => $url,
        ];
        $protected_b64 = Utils::b64_urlencode(Utils::jsonEncode($protected));
        $payload_b64 = is_null($payload) ? '' : Utils::b64_urlencode(Utils::jsonEncode($payload));
        $request = [
            'protected' => $protected_b64,
            'payload' => $payload_b64,
            'signature' => Utils::b64_urlencode($signer->sign($protected_b64 . '.' . $payload_b64)),
        ];
        return $request;
    }

    /**
     * @param string $url
     * @param array|object|null $payload
     */
    public function joseRequest(string $url, $payload = null)
    {
        $headers = ['Content-Type' => 'application/jose+json'];
        $jose = Utils::jsonEncode($this->formatRequest($url, $payload));
        $this->acme->httpClient()->post($url, $jose, $headers);
    }

    public function getRawEntity(string $url): array
    {
        $this->joseRequest($url);
        $result = $this->acme->internals()->parseResponse(true);
        return $result;
    }
}