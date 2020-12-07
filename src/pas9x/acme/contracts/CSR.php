<?php

namespace pas9x\acme\contracts;

interface CSR
{
    public function getCsrPem(): string;
    public function getPrivateKey(): PrivateKey;
}