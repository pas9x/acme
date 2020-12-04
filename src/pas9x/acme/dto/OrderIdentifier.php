<?php

namespace pas9x\acme\dto;

class OrderIdentifier
{
    const TYPE_DNS = 'dns';

    /** @var string $type */
    protected $type;

    /** @var string $value */
    protected $value;

    public function __construct(string $type, string $value)
    {
        $this->type = $type;
        $this->value = $value;
    }

    public function type(): string
    {
        return $this->type;
    }

    public function value(): string
    {
        return $this->value;
    }
}