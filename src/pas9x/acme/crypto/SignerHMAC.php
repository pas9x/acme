<?php

namespace pas9x\acme\crypto;

use pas9x\acme\enums\SignatureAlgorithm;
use phpseclib3\Crypt\Hash;

class SignerHMAC implements Signer
{
    public function __construct(
        public readonly SignatureAlgorithm $algorithm,
        protected readonly string $key,
    )
    {
    }

    public function sign(string $data): string
    {
        $hasher = new Hash($this->algorithm->toString());
        $hasher->setKey($this->key);
        return $hasher->hash($data);
    }

    public function alg(): string
    {
        return $this->algorithm->toNistCode('HS');
    }
}