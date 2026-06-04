<?php

namespace test;

use pas9x\acme\enums\ECKeyCurve;
use pas9x\acme\enums\KeyType;

class KeyParams
{

    public function __construct(
        public readonly KeyType $keyType,
        public readonly ?ECKeyCurve $curve,
        public readonly ?int $bits
    )
    {
    }

    public static function createRSA(int $bits): self
    {
        return new self(KeyType::RSA, null, $bits);
    }

    public static function createEC(ECKeyCurve $curve): self
    {
        return new self(KeyType::EC, $curve, null);
    }

    public function equals(KeyParams $params): bool
    {
        if ($params->keyType !== $this->keyType) {
            return false;
        }
        if ($params->curve !== $this->curve) {
            return false;
        }
        if ($params->bits !== $this->bits) {
            return false;
        }
        return true;
    }

    public function __toString(): string
    {
        $result = $this->keyType->toString() . '_';
        if ($this->keyType === KeyType::RSA) {
            $result .= $this->bits;
        } elseif ($this->keyType === KeyType::EC) {
            $result .= $this->curve->toNistCode();
        } else {
            throw new \LogicException('Unsupported key type: ' . $this->keyType->toString());
        }
        return $result;
    }
}