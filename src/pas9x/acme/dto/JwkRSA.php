<?php

namespace pas9x\acme\dto;

class JwkRSA
{
    public readonly string $kty;

    public function __construct(
        public readonly string $n,
        public readonly string $e,
    )
    {
        $this->kty = 'RSA';
    }
}