<?php

namespace pas9x\acme\dto;

class Certificate
{
    protected $certificate;
    protected $caChain;

    /**
     * @param string $certificate
     * @param string[] $caChain
     */
    public function __construct(string $certificate, array $caChain)
    {
        $this->certificate = $certificate;
        $this->caChain = $caChain;
    }

    public function certificate(): string
    {
        return $this->certificate;
    }

    /**
     * @return string[]
     */
    public function caCertificateChain(): array
    {
        return $this->caChain;
    }
}