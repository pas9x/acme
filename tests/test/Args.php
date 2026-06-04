<?php

namespace test;

class Args
{
    public readonly array $params;
    public readonly array $flags;

    public function __construct()
    {
        global $argv;

        $params = [];
        $flags = [];

        foreach ($argv as $arg) {
            $parts = explode('=', $arg, 2);
            $name = trim($parts[0]);
            $name = ltrim($name, '-');
            $name = trim($name);
            if (count($parts) === 2) {
                $params[$name] = trim($parts[2]);
            } else {
                $flags[] = $name;
            }
        }

        $this->params = $params;
        $this->flags = $flags;
    }

    public function getParam(string $name, mixed $defaultValue = null): mixed
    {
        return $this->params[$name] ?? $defaultValue;
    }

    public function hasFlag(string $name): bool
    {
        return in_array($name, $this->flags);
    }
}