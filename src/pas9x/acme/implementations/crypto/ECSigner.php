<?php

namespace pas9x\acme\implementations\crypto;

use InvalidArgumentException;
use LogicException;
use pas9x\acme\contracts\Signer;

class ECSigner implements Signer
{
    const ALG_ES256 = 'ES256';
    const ALG_ES384 = 'ES384';
    const ALG_ES512 = 'ES512';

    protected static $algs = [
        self::ALG_ES256 => 'sha256',
        self::ALG_ES384 => 'sha384',
        self::ALG_ES512 => 'sha512',
    ];

    /** @var ECPrivateKey $privateKey */
    protected $privateKey;

    /** @var string $algo */
    protected $alg;

    public function __construct(ECPrivateKey $privateKey, string $alg)
    {
        if (!isset(static::$algs[$alg])) {
            throw new InvalidArgumentException('Unsupported $alg: ' . $alg);
        }
        $this->alg = $alg;
        $this->privateKey = $privateKey;
    }

    public function sign(string $data): string
    {
        return $this->privateKey->sign($data, static::$algs[$this->alg]);
    }

    public function verify(string $data, string $signature): bool
    {
        $publicKey = $this->privateKey->getPublicKey();
        if ($publicKey instanceof ECPublicKey) {
            return $publicKey->verify($data, $signature, static::$algs[$this->alg]);
        } else {
            throw new LogicException;
        }
    }

    public function alg(): string
    {
        return $this->alg;
    }
}