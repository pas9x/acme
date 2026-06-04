<?php

namespace pas9x\acme\crypto;

use pas9x\acme\enums\SignatureAlgorithm;
use phpseclib3\Crypt\RSA;

class VerifierRSA implements Verifier
{
    public function __construct(
        protected readonly PublicKeyRSA $publicKeyRsa,
        public readonly SignatureAlgorithm $signatureAlgorithm
    )
    {
    }

    public function verify(string $data, string $signature): bool
    {
        $algo = $this->signatureAlgorithm->toString();
        $key = $this->publicKeyRsa->phpseclibPublicKey
            ->withPadding(RSA::SIGNATURE_PKCS1) // Use PKCS#1 v1.5 signature format instead of default RSA-PSS
            ->withHash($algo);
        return $key->verify($data, $signature);
    }
}