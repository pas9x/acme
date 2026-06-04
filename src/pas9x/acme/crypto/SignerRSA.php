<?php

namespace pas9x\acme\crypto;

use pas9x\acme\enums\SignatureAlgorithm;
use phpseclib3\Crypt\RSA;

class SignerRSA implements Signer
{
    public function __construct(
        protected readonly PrivateKeyRSA $privateKeyRsa,
        protected readonly SignatureAlgorithm $signatureAlgorithm
    )
    {
    }

    public function sign(string $data): string
    {
        $algo = $this->signatureAlgorithm->toString();
        $key = $this->privateKeyRsa->phpseclibPrivateKey
            //->withPadding(RSA::SIGNATURE_PKCS1) // Use PKCS#1 v1.5 signature format instead of default RSA-PSS
            ->withHash($algo);
        $signature = $key->sign($data);
        //echo 'RSA signature: ' . bin2hex($signature);
        return $signature;
    }

    public function alg(): string
    {
        return $this->signatureAlgorithm->toNistCode('RS');
    }
}