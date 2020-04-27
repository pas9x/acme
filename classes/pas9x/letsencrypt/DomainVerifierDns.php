<?php

namespace pas9x\letsencrypt;

abstract class DomainVerifierDns implements DomainVerifier
{
    /** @inheritdoc */
    public function challengeType()
    {
        return 'dns-01';
    }

    /** @inheritdoc */
    public function verify(VerificationData $verificationData)
    {
        $this->setTxtRecord($verificationData->txtRecord);
    }

    public abstract function setTxtRecord($value);
}