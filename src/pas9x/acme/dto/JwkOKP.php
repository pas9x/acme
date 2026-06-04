<?php

namespace pas9x\acme\dto;

class JwkOKP
{
    public readonly string $kty;

    public function __construct(
        public readonly string $crv,
        public readonly string $x,
    )
    {
        $this->kty = 'OKP';
    }
}