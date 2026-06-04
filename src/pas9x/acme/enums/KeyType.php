<?php

namespace pas9x\acme\enums;

enum KeyType
{
    case RSA;
    case EC;

    public function toString(): string
    {
        return match($this) {
            self::EC => 'EC',
            self::RSA => 'RSA',
            default => throw new \LogicException
        };
    }

    public static function fromString(string $keyType): self
    {
        return match($keyType) {
            'EC' => self::EC,
            'RSA' => self::RSA,
            default => throw new \ValueError('Unsupported key type: ' . $keyType)
        };
    }
}