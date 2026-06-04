<?php

namespace test;

use pas9x\acme\enums\SignatureAlgorithm;

class OpenSSL
{
    protected static function getHashAlgo(SignatureAlgorithm $algo): int
    {
        if ($algo === SignatureAlgorithm::SHA256) {
            return OPENSSL_ALGO_SHA256;
        }
        if ($algo === SignatureAlgorithm::SHA384) {
            return OPENSSL_ALGO_SHA384;
        }
        if ($algo === SignatureAlgorithm::SHA512) {
            return OPENSSL_ALGO_SHA512;
        }
        throw new \LogicException('Unsupported algo: ' . $algo->toString());
    }

    public static function getPrivateKey(string $privateKeyPem): \OpenSSLAsymmetricKey
    {
        $opensslPrivateKey = openssl_pkey_get_private($privateKeyPem);
        if ($opensslPrivateKey instanceof \OpenSSLAsymmetricKey) {
            return $opensslPrivateKey;
        } else {
            throw new \RuntimeException('Failed to open private key with openssl');
        }
    }

    public static function getPublicKey(string $privateKeyPem): \OpenSSLAsymmetricKey
    {
        $opensslPrivateKey = openssl_pkey_get_public($privateKeyPem);
        if ($opensslPrivateKey instanceof \OpenSSLAsymmetricKey) {
            return $opensslPrivateKey;
        } else {
            throw new \RuntimeException('Failed to open public key with openssl');
        }
    }

    public static function sign(string $data, \OpenSSLAsymmetricKey $opensslPrivateKey, ?SignatureAlgorithm $signatureAlgorithm): string
    {
        $algo = is_null($signatureAlgorithm) ? 0 : self::getHashAlgo($signatureAlgorithm);
        $signature = null;
        $ok = openssl_sign($data, $signature, $opensslPrivateKey, $algo);
        if ($ok !== true || !is_string($signature) || $signature === '') {
            throw new \RuntimeException('openssl_sign() failed');
        }
        return $signature;
    }

    public static function verify(string $data, string $signature, \OpenSSLAsymmetricKey $opensslPublicKey, ?SignatureAlgorithm $signatureAlgorithm): bool
    {
        $algo = is_null($signatureAlgorithm) ? 0 : self::getHashAlgo($signatureAlgorithm);
        $status = openssl_verify($data, $signature, $opensslPublicKey, $algo);
        return $status === 1;
    }
}