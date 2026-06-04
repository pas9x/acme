<?php

namespace pas9x\acme\dto;

class OrderIdentifier
{
    const TYPE_DNS = 'dns';

    public function __construct(
        public readonly string $type,
        public readonly string $value
    )
    {
    }
}