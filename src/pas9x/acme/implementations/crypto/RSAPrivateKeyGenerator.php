<?php

namespace pas9x\acme\implementations\crypto;

use Exception;
use LogicException;
use pas9x\acme\Utils;
use phpseclib\Crypt\RSA;
use pas9x\acme\ACME_internals;
use pas9x\acme\contracts\PrivateKey;
use pas9x\acme\contracts\PrivateKeyGenerator;

class RSAPrivateKeyGenerator implements PrivateKeyGenerator
{
    protected $bits;
    protected $engine;

    public function __construct(int $bits, string $engine = null)
    {
        $this->bits = $bits;
        if ($engine === null) {
            if (Utils::engineAvailable(Utils::ENGINE_OPENSSL)) {
                $this->engine = Utils::ENGINE_OPENSSL;
            } elseif (Utils::engineAvailable(Utils::ENGINE_PHPSECLIB)) {
                $this->engine = Utils::ENGINE_PHPSECLIB;
            } else {
                throw new Exception('No engine to generate RSA private key');
            }
        } else {
            if (!Utils::engineAvailable($engine)) {
                throw new Exception($engine . ' engine is not available');
            }
            if ($engine !== Utils::ENGINE_OPENSSL && $engine !== Utils::ENGINE_PHPSECLIB) {
                throw new Exception('Invalid $engine: ' . $engine);
            }
            $this->engine = $engine;
        }
    }

    public function generatePrivateKey(): PrivateKey
    {
        if ($this->engine === Utils::ENGINE_OPENSSL) {
            return $this->generateByOpenssl();
        } elseif ($this->engine === Utils::ENGINE_PHPSECLIB) {
            return $this->generateByPhpseclib();
        } else {
            throw new LogicException;
        }
    }

    protected function generateByOpenssl(): RSAPrivateKey
    {
        $config = [
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => $this->bits,
        ];
        $key = openssl_pkey_new($config);
        if (empty($key)) {
            throw new Exception('openssl_pkey_new() failed');
        }
        $ok = openssl_pkey_export($key, $privateKeyPem);
        if (!$ok || !is_string($privateKeyPem) || $privateKeyPem === '') {
            throw new Exception('openssl_pkey_export() failed');
        }
        return new RSAPrivateKey($privateKeyPem, $this->engine);
    }

    protected function generateByPhpseclib(): RSAPrivateKey
    {
        $rsa = new RSA;
        $key = $rsa->createKey($this->bits);
        if (!isset($key['privatekey']) || !is_string($key['privatekey']) || $key['privatekey'] === '') {
            throw new Exception('phpseclib createKey() failed');
        }
        return new RSAPrivateKey($key['privatekey'], $this->engine);
    }
}