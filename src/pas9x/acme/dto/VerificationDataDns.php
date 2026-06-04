<?php

namespace pas9x\acme\dto;

class VerificationDataDns
{
    public readonly string $txtRecordName;

    public function __construct(
        public readonly string $txtRecordValue
    )
    {
        $this->txtRecordName = '_acme-challenge';
    }
}