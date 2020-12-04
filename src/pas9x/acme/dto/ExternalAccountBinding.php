<?php

namespace pas9x\acme\dto;

use \pas9x\acme\contracts\Signer;

class ExternalAccountBinding
{
    /** @var string $kid */
    protected $kid;

    /** @var string $key */
    protected $key;

    /** @var Signer $signer */
    protected $signer;

    public function __construct(string $kid, string $key, Signer $signer = null)
    {
        $this->kid = $kid;
        $this->key = $key;
        $this->signer = $signer;
    }

    public function kid(): string
    {
        return $this->kid;
    }

    public function key(): string
    {
        return $this->key;
    }

    public function signer(): ?Signer
    {
        return $this->signer;
    }
}