<?php

namespace pas9x\acme\crypto;

interface Verifier
{
    public function verify(string $data, string $signature): bool;
}