<?php

namespace pas9x\acme\enums;

enum ECKeyCurve
{
    case P256;
    case P384;
    case P521;
    case ED448;
    case ED25519;

    /**
     * @see https://datatracker.ietf.org/doc/html/rfc8422#appendix-A
     * @see https://datatracker.ietf.org/doc/html/rfc8037#section-3.1
     * @return string
     */
    public function toNistCode(): string
    {
        return match ($this) {
            self::P256 => 'P-256',
            self::P384 => 'P-384',
            self::P521 => 'P-521',
            self::ED448 => 'Ed448',
            self::ED25519 => 'Ed25519',
            default => throw new \LogicException
        };
    }

    public static function fromNistCode(string $nistCurveCode): self
    {
        return match (strtoupper($nistCurveCode)) {
            'P-256' => self::P256,
            'P-384' => self::P384,
            'P-521' => self::P521,
            'ED448' => self::ED448,
            'ED25519' => self::ED25519,
            default => throw new \ValueError('Unsupported NIST EC curve: ' . $nistCurveCode)
        };
    }

    public function toPhpseclibCode(): string
    {
        return match ($this) {
            self::P256 => 'prime256v1',
            self::P384 => 'secp384r1',
            self::P521 => 'secp521r1',
            self::ED448 => 'Ed448',
            self::ED25519 => 'Ed25519',
            default => throw new \LogicException
        };
    }

    public static function fromPhpseclibCode(string $phpseclibCode): self
    {
        return match (strtolower($phpseclibCode)) {
            'prime256v1' => self::P256,
            'secp256r1' => self::P256,
            'secp384r1' => self::P384,
            'secp521r1' => self::P521,
            'ed448' => self::ED448,
            'ed25519' => self::ED25519,
            default => throw new \ValueError('Unsupported phpseclib curve: ' . $phpseclibCode)
        };
    }
}