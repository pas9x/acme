<?php

namespace pas9x\acme\implementations\crypto;

use Exception;
use InvalidArgumentException;
use LogicException;
use pas9x\acme\Utils;
use phpseclib\Crypt\Hash;
use pas9x\acme\contracts\Signer;
use pas9x\acme\ACME_internals;

class HMACSigner implements Signer
{
    const ALG_HS256 = 'HS256';
    const ALG_HS384 = 'HS384';
    const ALG_HS512 = 'HS512';

    protected static $algs = [
        self::ALG_HS256 => 'sha256',
        self::ALG_HS384 => 'sha384',
        self::ALG_HS512 => 'sha512',
    ];

    /** @var static $key */
    protected $key;
    protected $alg;
    protected $engine;

    public function __construct(string $key, string $alg, string $engine = null)
    {
        if (!isset(static::$algs[$alg])) {
            throw new InvalidArgumentException('Unsupported $alg: ' . $alg);
        }

        if ($engine === null) {
            if (Utils::engineAvailable(Utils::ENGINE_HASH)) {
                $this->engine = Utils::ENGINE_HASH;
            } elseif (Utils::engineAvailable(Utils::ENGINE_PHPSECLIB)) {
                $this->engine = Utils::ENGINE_PHPSECLIB;
            } else {
                throw new Exception('No engine available to make HMAC hash');
            }
        } else {
            if (!Utils::engineAvailable($engine)) {
                throw new Exception($engine . ' engine is not available');
            }
            if ($engine !== Utils::ENGINE_HASH && $engine !== Utils::ENGINE_PHPSECLIB) {
                throw new Exception('Invalid $engine: ' . $engine);
            }
            $this->engine = $engine;
        }

        $this->key = $key;
        $this->alg = $alg;
    }

    public function sign(string $data): string
    {
        if ($this->engine === Utils::ENGINE_HASH) {
            $result = hash_hmac(static::$algs[$this->alg], $data, $this->key, true);
            return $result;
        }

        if ($this->engine === Utils::ENGINE_PHPSECLIB) {
            $hasher = new Hash(static::$algs[$this->alg]);
            $hasher->setKey($this->key);
            $result = $hasher->hash($data);
            if (is_string($result) && $result !== '') {
                return $result;
            } else {
                throw new Exception('phpseclib hash() failed');
            }
        }

        throw new LogicException;
    }

    public function verify(string $data, string $signature): bool
    {
        $validSignature = $this->sign($data);
        return ($signature === $validSignature);
    }

    public function alg(): string
    {
        return $this->alg;
    }
}