<?php

namespace pas9x\acme\dto;

class VerificationDataFile
{
    public readonly string $dir;

    public function __construct(
        public readonly string $fileName,
        public readonly string $content
    )
    {
        $this->dir = '/.well-known/acme-challenge';
    }
}