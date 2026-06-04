<?php

namespace pas9x\acme\crypto;

use pas9x\acme\enums\ECKeyCurve;
use pas9x\acme\enums\SignatureAlgorithm;

class SignerEC implements Signer
{
    public bool $asn1SignatureFormat = false;

    public function __construct(
        protected readonly PrivateKeyEC $privateKeyEc,
        protected readonly ?SignatureAlgorithm $signatureAlgorithm
    )
    {
    }

    public function sign(string $data): string
    {
        if ($this->signatureAlgorithm === null) {
            $key = $this->privateKeyEc->phpseclibPrivateKey;
        } else {
            $algo = $this->signatureAlgorithm->toString();
            $key = $this->privateKeyEc->phpseclibPrivateKey->withHash($algo);
        }
        if (!$this->asn1SignatureFormat) {
            $key = $key->withSignatureFormat('IEEE');
        }
        $signature = $key->sign($data);
        return $signature;
    }

    public function alg(): string
    {
        if (in_array($this->privateKeyEc->curve, [ECKeyCurve::ED448, ECKeyCurve::ED25519])) {
            return 'EdDSA';
        }
        if (in_array($this->privateKeyEc->curve, [ECKeyCurve::P256, ECKeyCurve::P384, ECKeyCurve::P521])) {
            return $this->signatureAlgorithm->toNistCode('ES');
        }
        throw new \LogicException('Unexpected curve');
    }
}