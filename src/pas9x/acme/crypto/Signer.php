<?php

namespace pas9x\acme\crypto;

interface Signer
{
    public function sign(string $data): string;
    public function alg(): string;
}