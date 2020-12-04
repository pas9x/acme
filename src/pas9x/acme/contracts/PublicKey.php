<?php

namespace pas9x\acme\contracts;

interface PublicKey
{
    /**
     * @return string
     */
    public function getPublicKeyPem(): string;

    /**
     * https://tools.ietf.org/html/rfc7517#page-25
     * @return array
     */
    public function getJWK(): array;

    /**
     * https://tools.ietf.org/html/rfc7638#page-4
     * @return string
     */
    public function thumbprint(): string;
}