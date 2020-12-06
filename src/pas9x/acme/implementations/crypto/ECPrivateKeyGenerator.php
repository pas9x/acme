<?php

namespace pas9x\acme\implementations\crypto;

use Exception;
use pas9x\acme\contracts\PrivateKey;
use pas9x\acme\contracts\PrivateKeyGenerator;
use pas9x\acme\Utils;

class ECPrivateKeyGenerator implements PrivateKeyGenerator
{
    protected $curve;

    public function __construct(string $curve)
    {
        if (!Utils::engineAvailable(Utils::ENGINE_OPENSSL)) {
            throw new Exception('EC keys requires openssl php module');
        }
        $this->curve = $curve;
    }

    public function generatePrivateKey(): PrivateKey
    {
        return $this->generateByOpenssl();
    }

    protected function generateByOpenssl(): ECPrivateKey
    {
        if (!isset(ECPrivateKey::CURVE_TO_OPENSSL[$this->curve])) {
            throw new Exception('Unsupported curve: ' . $this->curve);
        }
        $config = [
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => ECPrivateKey::CURVE_TO_OPENSSL[$this->curve],
        ];
        $key = openssl_pkey_new($config);
        if (empty($key)) {
            throw new Exception('openssl_pkey_new() failed');
        }
        $ok = openssl_pkey_export($key, $privateKeyPem);
        if (!$ok || !is_string($privateKeyPem) || $privateKeyPem === '') {
            throw new Exception('openssl_pkey_export() failed');
        }
        return new ECPrivateKey($privateKeyPem);
    }
}