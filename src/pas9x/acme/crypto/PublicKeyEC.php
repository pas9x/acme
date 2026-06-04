<?php

namespace pas9x\acme\crypto;

use pas9x\acme\dto\JwkEC;
use pas9x\acme\dto\JwkOKP;
use pas9x\acme\enums\ECKeyCurve;
use pas9x\acme\enums\KeyType;
use pas9x\acme\enums\SignatureAlgorithm;
use phpseclib3\Crypt\EC\PublicKey as PhpSeclibPublicKeyEC;

class PublicKeyEC extends PublicKey
{
    public readonly PhpSeclibPublicKeyEC $phpseclibPublicKey;
    public readonly KeyType $keyType;
    public readonly ECKeyCurve $curve;

    public function __construct(string|PhpSeclibPublicKeyEC $publicKey)
    {
        $this->setDelegate();
        $this->phpseclibPublicKey = self::load($publicKey, PhpSeclibPublicKeyEC::class);
        $this->keyType = KeyType::EC;
        $this->curve = ECKeyCurve::fromPhpseclibCode($this->phpseclibPublicKey->getCurve());
    }

    public function getDefaultVerifier(): VerifierEC
    {
        return match($this->curve) {
            ECKeyCurve::P256 => new VerifierEC($this, SignatureAlgorithm::SHA256),
            ECKeyCurve::P384 => new VerifierEC($this, SignatureAlgorithm::SHA384),
            ECKeyCurve::P521 => new VerifierEC($this, SignatureAlgorithm::SHA512),
            ECKeyCurve::ED448 => new VerifierEC($this, null),
            ECKeyCurve::ED25519 => new VerifierEC($this, null),
            default => throw new \LogicException('Unexpected curve')
        };
    }

    public function getVerifier(?SignatureAlgorithm $signatureAlgorithm): VerifierEC
    {
        return new VerifierEC($this, $signatureAlgorithm);
    }

    public function getJwk(): JwkEC|JwkOKP
    {
        $raw = $this->getRawJwk();
        if ($raw->kty === 'EC') {
            $jwk = new JwkEC($raw->crv, $raw->x, $raw->y);
        } elseif ($raw->kty === 'OKP') {
            $jwk = new JwkOKP($raw->crv, $raw->x);
        } else {
            throw new \LogicException('Unexpected jwk key type: ' . $raw->kty);
        }
        return $jwk;
    }

    public function getThumbprint(): string
    {
        // We need to create an STRICT json string to get the valid hash
        $jwk = $this->getJwk();
        if (in_array($this->curve, [ECKeyCurve::P256, ECKeyCurve::P384, ECKeyCurve::P521])) {
            $result = '{"crv":"' . $jwk->crv . '","kty":"' . $jwk->kty . '","x":"' . $jwk->x . '","y":"' . $jwk->y . '"}';
        } elseif (in_array($this->curve, [ECKeyCurve::ED448, ECKeyCurve::ED25519])) {
            $result = '{"crv":"' . $jwk->crv . '","kty":"' . $jwk->kty . '","x":"' . $jwk->x . '"}';
        } else {
            throw new \LogicException('Unexpected curve');
        }
        return $result;
    }
}