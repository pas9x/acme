<?php

namespace pas9x\acme\crypto;

use pas9x\acme\enums\KeyType;
use pas9x\acme\Utils;
use phpseclib3\Crypt\Common\PrivateKey as PhpseclibPrivateKey;
use phpseclib3\Crypt\EC\PrivateKey as PhpseclibPrivateKeyEC;
use phpseclib3\Crypt\RSA\PrivateKey as PhpseclibPrivateKeyRSA;
use phpseclib3\Crypt\PublicKeyLoader;

class PrivateKey
{
    public readonly KeyType $keyType;

    /** @var PrivateKeyEC|PrivateKeyRSA */
    public readonly self $delegate;

    public function __construct(string|PhpseclibPrivateKey $publicKey)
    {
        $phpseclibKey = self::load($publicKey);
        if ($phpseclibKey instanceof PhpseclibPrivateKeyRSA) {
            $this->delegate = new PrivateKeyRSA($phpseclibKey);
        } elseif ($phpseclibKey instanceof PhpseclibPrivateKeyEC) {
            $this->delegate = new PrivateKeyEC($phpseclibKey);
        } else {
            throw new \ValueError('Unsupported private key type: ' . get_class($phpseclibKey));
        }
        $this->keyType = $this->delegate->keyType;
    }

    protected function setDelegate()
    {
        $this->delegate = $this;
    }

    public function getDefaultSigner(): Signer
    {
        return $this->delegate->getDefaultSigner();
    }

    public function getPrivateKeyPem(): string
    {
        return $this->delegate->phpseclibPrivateKey->toString('PKCS8');
    }

    public function getPublicKey(): PublicKeyRSA|PublicKeyEC
    {
        return $this->delegate->getPublicKey();
    }

    protected static function load($privateKey, ?string $needClass = null): PhpseclibPrivateKey
    {
        if (is_string($privateKey)) {
            $phpseclibKey = PublicKeyLoader::loadPrivateKey($privateKey);
            if (!($phpseclibKey instanceof PhpseclibPrivateKey)) {
                throw new \ValueError('Failed to load private key');
            }
        } elseif ($privateKey instanceof PhpseclibPrivateKey) {
            $phpseclibKey = $privateKey;
        } else {
            throw new \InvalidArgumentException('Invalid type of $privateKey: ' . Utils::gettype($privateKey));
        }
        if ($needClass !== null) {
            if (!($phpseclibKey instanceof $needClass)) {
                throw new \ValueError("This is not an $needClass key. Actual key type: " . get_class($phpseclibKey));
            }
        }
        return $phpseclibKey;
    }
}