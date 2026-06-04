<?php

namespace pas9x\acme\dto;

use pas9x\acme\crypto\Certificate;

class RegisteredCertificate
{
    /**
     * @param Certificate $certificate
     * @param array<string,Certificate> $caChain
     */
    public function __construct(
        public readonly Certificate $certificate,
        public readonly array $caChain
    )
    {
    }

    /**
     * @param string[] $caChainPems
     * @return array<string,Certificate>
     */
    public static function wrapChain(array $caChainPems): array
    {
        $result = [];
        foreach ($caChainPems as $caCertPem) {
            $caCert = new Certificate($caCertPem);
            $result[$caCert->subjectKeyIdentifier] = $caCert;
        }
        return $result;
    }

    /**
     * @return string[]
     */
    public function getChainPems(): array
    {
        $pems = [];
        foreach ($this->caChain as $caCert) {
            $pems[$caCert->subjectKeyIdentifier] = $caCert->pem;
        }
        return $pems;
    }
}