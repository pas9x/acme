<?php

namespace pas9x\acme\contracts;

interface PrivateKeyGenerator
{
    public function generatePrivateKey(): PrivateKey;
}