<?php

namespace pas9x\acme\dto;

use \pas9x\acme\crypto\Signer;

class ExternalAccountBinding
{
    public function __construct(
        public readonly string $kid,
        public readonly string $key,
        public readonly ?Signer $signer = null
    )
    {
    }
}