<?php

namespace pas9x\acme\contracts;

interface Signer
{
    public function sign(string $data): string;
    public function verify(string $data, string $signature): bool;
    public function alg(): string;
}