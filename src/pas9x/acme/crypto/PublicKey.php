<?php

namespace pas9x\acme\crypto;

use pas9x\acme\dto\JwkEC;
use pas9x\acme\dto\JwkOKP;
use pas9x\acme\dto\JwkRSA;
use pas9x\acme\enums\KeyType;
use pas9x\acme\Utils;
use phpseclib3\Crypt\Common\PublicKey as PhpseclibPublicKey;
use phpseclib3\Crypt\EC\PublicKey as PhpseclibPublicKeyEC;
use phpseclib3\Crypt\RSA\PublicKey as PhpseclibPublicKeyRSA;
use phpseclib3\Crypt\PublicKeyLoader;

class PublicKey
{
    /**
     * @var PublicKeyEC|PublicKeyRSA
     */
    public readonly self $delegate;
    public readonly KeyType $keyType;

    public function __construct(string|PhpseclibPublicKey $publicKey)
    {
        $phpseclibKey = self::load($publicKey);
        if ($phpseclibKey instanceof PhpseclibPublicKeyRSA) {
            $this->delegate = new PublicKeyRSA($phpseclibKey);
        } elseif ($phpseclibKey instanceof PhpseclibPublicKeyEC) {
            $this->delegate = new PublicKeyEC($phpseclibKey);
        } else {
            throw new \ValueError('Unsupported public key type: ' . get_class($phpseclibKey));
        }
        $this->keyType = $this->delegate->keyType;
    }

    protected function setDelegate()
    {
        $this->delegate = $this;
    }

    public function getDefaultVerifier(): Verifier
    {
        return $this->delegate->getDefaultVerifier();
    }

    protected function getRawJwk(): object
    {
        $json = $this->delegate->phpseclibPublicKey->toString('JWK');
        $object = Utils::jsonDecode($json);
        if (empty($object->keys[0]->kty)) {
            throw new \LogicException('Failed to export public key to JWK with phpseclib');
        }
        return $object->keys[0];
    }

    public function getJwk(): JwkRSA|JwkEC|JwkOKP
    {
        return $this->delegate->getJwk();
    }

    public function getThumbprint(): string
    {
        return $this->delegate->getThumbprint();
    }

    public function getPublicKeyPem(): string
    {
        return $this->delegate->phpseclibPublicKey->toString('PKCS8');
    }

    protected static function load($publicKey, ?string $needClass = null): PhpseclibPublicKey
    {
        if (is_string($publicKey)) {
            $phpseclibKey = PublicKeyLoader::loadPublicKey($publicKey);
            if (!($phpseclibKey instanceof PhpseclibPublicKey)) {
                throw new \ValueError('Failed to load public key');
            }
        } elseif ($publicKey instanceof PhpseclibPublicKey) {
            $phpseclibKey = $publicKey;
        } else {
            throw new \InvalidArgumentException('Invalid type of $publicKey: ' . Utils::gettype($publicKey));
        }
        if ($needClass !== null) {
            if (!($phpseclibKey instanceof $needClass)) {
                throw new \ValueError("This is not an $needClass key. Actual key type: " . get_class($phpseclibKey));
            }
        }
        return $phpseclibKey;
    }
}