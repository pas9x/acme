<?php

namespace pas9x\acme\crypto;

use pas9x\acme\enums\SignatureAlgorithm;

class VerifierEC implements Verifier
{
    public bool $asn1SignatureFormat = false;

    public function __construct(
        protected readonly PublicKeyEC $publicKeyEc,
        public readonly ?SignatureAlgorithm $signatureAlgorithm
    )
    {
    }

    public function verify(string $data, string $signature): bool
    {
        if ($this->signatureAlgorithm === null) {
            $key = $this->publicKeyEc->phpseclibPublicKey;
        } else {
            $algo = $this->signatureAlgorithm->toString();
            $key = $this->publicKeyEc->phpseclibPublicKey->withHash($algo);
        }
        if (!$this->asn1SignatureFormat) {
            $key = $key->withSignatureFormat('IEEE');
        }
        return $key->verify($data, $signature);
    }
}