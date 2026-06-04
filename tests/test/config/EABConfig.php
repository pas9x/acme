<?php

namespace test\config;

class EABConfig
{
    public readonly string $kid;
    public readonly string $key;

    public function __construct(array $raw)
    {
        $this->kid = $raw['kid'];
        $this->key = $raw['key'];
    }
}