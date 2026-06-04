<?php

namespace pas9x\acme\dto;

class VerificationData
{
    public function __construct(
        public readonly VerificationDataFile $file,
        public readonly VerificationDataDns $dns
    )
    {
    }
}
