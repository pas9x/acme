<?php

namespace pas9x\acme\crypto;

use pas9x\acme\enums\KeyType;
use pas9x\acme\enums\SignatureAlgorithm;
use pas9x\acme\Utils;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\PrivateKey as PhpseclibPrivateKeyRSA;

class PrivateKeyRSA extends PrivateKey
{
    public readonly KeyType $keyType;
    public readonly int $bits;
    public readonly PhpseclibPrivateKeyRSA $phpseclibPrivateKey;
    private ?PublicKeyRSA $publicKey = null;

    public function __construct(string|PhpseclibPrivateKeyRSA $privateKey)
    {
        $this->keyType = KeyType::RSA;
        $this->setDelegate();
        /** @var PhpseclibPrivateKeyRSA $phpseclibPrivateKey */
        $phpseclibPrivateKey = self::load($privateKey, PhpseclibPrivateKeyRSA::class);
        $this->phpseclibPrivateKey = $phpseclibPrivateKey->withPadding(RSA::SIGNATURE_PKCS1); // Use PKCS#1 v1.5 signature format instead of default RSA-PSS
        $this->bits = $this->phpseclibPrivateKey->getLength();
    }

    public function getDefaultSigner(): SignerRSA
    {
        return $this->getSigner(SignatureAlgorithm::SHA256);
    }

    public function getSigner(SignatureAlgorithm $signatureAlgorithm): SignerRSA
    {
        return new SignerRSA($this, $signatureAlgorithm);
    }

    public function getPublicKey(): PublicKeyRSA
    {
        if ($this->publicKey === null) {
            $phpseclibPublicKey = $this->phpseclibPrivateKey->getPublicKey();
            $this->publicKey = new PublicKeyRSA($phpseclibPublicKey);
        }
        return $this->publicKey;
    }

    public static function generate(int $bits): self
    {
        $key = RSA::createKey($bits);
        if ($key instanceof PhpseclibPrivateKeyRSA) {
            return new self($key);
        }
        throw new \LogicException('Phpseclib RSA::createKey() failed. Result type = ' . Utils::gettype($key));
    }
}