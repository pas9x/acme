<?php

namespace pas9x\acme\dto;

class JwkEC
{
    public readonly string $kty;

    public function __construct(
        public readonly string $crv,
        public readonly string $x,
        public readonly string $y,
    )
    {
        $this->kty = 'EC';
    }
}