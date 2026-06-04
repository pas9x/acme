<?php

namespace pas9x\acme\crypto;

use pas9x\acme\dto\JwkRSA;
use pas9x\acme\enums\KeyType;
use pas9x\acme\enums\SignatureAlgorithm;
use phpseclib3\Crypt\RSA\PublicKey as PhpseclibPublicKeyRSA;

class PublicKeyRSA extends PublicKey
{
    public readonly PhpseclibPublicKeyRSA $phpseclibPublicKey;
    public readonly KeyType $keyType;
    public readonly int $bits;

    public function __construct(string|PhpseclibPublicKeyRSA $publicKey)
    {
        $this->setDelegate();
        $this->phpseclibPublicKey = self::load($publicKey, PhpseclibPublicKeyRSA::class);
        $this->keyType = KeyType::RSA;
        $this->bits = $this->phpseclibPublicKey->getLength();
    }

    public function getDefaultVerifier(): VerifierRSA
    {
        return $this->getVerifier(SignatureAlgorithm::SHA256);
    }

    public function getVerifier(SignatureAlgorithm $signatureAlgorithm): VerifierRSA
    {
        return new VerifierRSA($this, $signatureAlgorithm);
    }

    public function getJwk(): JwkRSA
    {
        $raw = $this->getRawJwk();
        if ($raw->kty === 'RSA') {
            return new JwkRSA($raw->n, $raw->e);
        } else {
            throw new \LogicException('Unexpected jwk key type: ' . $raw->kty);
        }
    }

    public function getThumbprint(): string
    {
        $jwk = $this->getJwk();
        // We need to create an STRICT json string to get the valid hash
        $result = '{"e":"' . $jwk->e . '","kty":"' . $jwk->kty . '","n":"' . $jwk->n . '"}';
        return $result;
    }
}