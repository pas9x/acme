<?php

namespace pas9x\acme\dto;

class SanName
{
    public const TYPE_DNS = 'DNS';
    public const TYPE_IP = 'IP';

    public function __construct(
        public readonly string $type,
        public readonly string $value
    )
    {
    }

    public function __toString(): string
    {
        return $this->type . ':' . $this->value;
    }
}