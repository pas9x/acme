<?php

namespace test\config;

class Config
{
    /** @var array<string,CAConfig> $ca */
    public readonly array $ca;

    public function __construct(array $raw)
    {
        $ca = [];
        foreach ($raw['ca'] as $name => $caRaw) {
            $ca[$name] = new CAConfig($name, $caRaw);
        }
        $this->ca = $ca;
    }

    public static function loadFromFile(string $configPath): self
    {
        $raw = require $configPath;
        return new self($raw);
    }
}