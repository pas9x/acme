<?php

namespace pas9x\acme\enums;

enum SignatureAlgorithm
{
    case SHA256;
    case SHA384;
    case SHA512;

    public function toNistCode(string $prefix): string
    {
        return match ($this) {
            self::SHA256 => $prefix . '256',
            self::SHA384 => $prefix . '384',
            self::SHA512 => $prefix . '512',
            default => throw new \LogicException,
        };
    }

    public function toString(bool $upperCase = false): string
    {
        return match ($this) {
            self::SHA256 => $upperCase ? 'SHA256' : 'sha256',
            self::SHA384 => $upperCase ? 'SHA384' : 'sha384',
            self::SHA512 => $upperCase ? 'SHA512' : 'sha512',
            default => throw new \LogicException,
        };
    }
}