<?php

namespace pas9x\acme\contracts;

interface PrivateKey
{
    public function getPrivateKeyPem(): string;
    public function getPublicKey(): PublicKey;
}