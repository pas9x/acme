<?php

namespace pas9x\acme\implementations\crypto;

use InvalidArgumentException;
use LogicException;
use pas9x\acme\contracts\Signer;

class RSASigner implements Signer
{
    const ALG_RS256 = 'RS256';
    const ALG_RS384 = 'RS384';
    const ALG_RS512 = 'RS512';

    protected static $algs = [
        self::ALG_RS256 => 'sha256',
        self::ALG_RS384 => 'sha384',
        self::ALG_RS512 => 'sha512',
    ];

    /** @var RSAPrivateKey $privateKey */
    protected $privateKey;

    /** @var string $algo */
    protected $alg;

    public function __construct(RSAPrivateKey $privateKey, string $alg)
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
        if ($publicKey instanceof RSAPublicKey) {
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