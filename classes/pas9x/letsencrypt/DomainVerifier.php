<?php

namespace pas9x\letsencrypt;

interface DomainVerifier
{
    /** @return string */
    public function domainName();

    /** @return string */
    public function challengeType();

    /**
     * @param VerificationData $verificationData
     * @throws \Exception
     */
    public function verify(VerificationData $verificationData);

    public function cleanup();
}