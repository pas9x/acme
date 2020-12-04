<?php

class Config
{
    /** @var array $config */
    protected $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    public static function loadFromFile(string $fileName): self
    {
        if (!file_exists($fileName)) {
            throw new Exception("Config file $fileName does not exist");
        }
        if (is_dir($fileName)) {
            throw new Exception($fileName . ' is directory');
        }
        if (!is_readable($fileName)) {
            throw new Exception("Config file $fileName is not readable");
        }
        $config = require $fileName;
        if (is_array($config)) {
            return new self($config);
        } else {
            throw new Exception("Return type of $fileName is " . gettype($config) . ", but array need");
        }
    }

    public function get(string $parameter, $defaultValue = null)
    {
        $path = explode('.', $parameter);
        $pathDepth = count($path);
        $hasDefaultValue = func_num_args() > 1;

        $config = $this->config;
        for ($j = 0; $j < $pathDepth; $j++) {
            $key = $path[$j];
            if (!isset($config[$key])) {
                if ($hasDefaultValue) return $defaultValue;
                else throw new Exception("Configuration parameter $parameter not found (1)");
            }
            $value = $config[$key];
            if ($j === $pathDepth - 1) {
                return $value;
            }
            if (!is_array($value)) {
                if ($hasDefaultValue) return $defaultValue;
                else throw new Exception("Configuration parameter $parameter not found (2)");
            }
            $config = $value;
        }

        if ($hasDefaultValue) {
            return $defaultValue;
        }
        throw new Exception("Configuration parameter $parameter not found (3)");
    }

    public function getFullConfig(): array
    {
        return $this->config;
    }
}