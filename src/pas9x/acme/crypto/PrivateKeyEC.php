<?php

namespace pas9x\acme\crypto;

use pas9x\acme\enums\ECKeyCurve;
use pas9x\acme\enums\KeyType;
use pas9x\acme\enums\SignatureAlgorithm;
use pas9x\acme\Utils;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\EC\PrivateKey as PhpseclibPrivateKeyEC;

class PrivateKeyEC extends PrivateKey
{
    public readonly KeyType $keyType;
    public readonly ECKeyCurve $curve;
    public readonly PhpseclibPrivateKeyEC $phpseclibPrivateKey;
    protected ?PublicKeyEC $publicKey = null;

    public function __construct(string|PhpseclibPrivateKeyEC $privateKey)
    {
        $this->keyType = KeyType::EC;
        $this->setDelegate();
        $this->phpseclibPrivateKey = self::load($privateKey, PhpseclibPrivateKeyEC::class);
        $this->curve = ECKeyCurve::fromPhpseclibCode($this->phpseclibPrivateKey->getCurve());
    }

    public function getDefaultSigner(): SignerEC
    {
        return match($this->curve) {
            ECKeyCurve::P256 => new SignerEC($this, SignatureAlgorithm::SHA256),
            ECKeyCurve::P384 => new SignerEC($this, SignatureAlgorithm::SHA384),
            ECKeyCurve::P521 => new SignerEC($this, SignatureAlgorithm::SHA512),
            ECKeyCurve::ED448 => new SignerEC($this, null),
            ECKeyCurve::ED25519 => new SignerEC($this, null),
            default => throw new \LogicException('Unexpected curve')
        };
    }

    public function getSigner(?SignatureAlgorithm $signatureAlgorithm): SignerEC
    {
        return new SignerEC($this, $signatureAlgorithm);
    }

    public function getPublicKey(): PublicKeyEC
    {
        if ($this->publicKey === null) {
            $phpseclibPublicKey = $this->phpseclibPrivateKey->getPublicKey();
            $this->publicKey = new PublicKeyEC($phpseclibPublicKey);
        }
        return $this->publicKey;
    }

    public static function generate(ECKeyCurve $curve): self
    {
        $key = EC::createKey($curve->toPhpseclibCode());
        if ($key instanceof PhpseclibPrivateKeyEC) {
            return new self($key);
        }
        throw new \LogicException('Phpseclib EC::createKey() failed. Result type = ' . Utils::gettype($key));
    }
}