<?php

namespace pas9x\acme\implementations\crypto;

use Exception;
use InvalidArgumentException;
use LogicException;
use pas9x\acme\Utils;
use phpseclib\Crypt\RSA;
use pas9x\acme\ACME_internals;
use pas9x\acme\contracts\PrivateKey;
use pas9x\acme\contracts\PublicKey;
use pas9x\acme\contracts\Signer;

class RSAPrivateKey implements PrivateKey
{
    /** @var string $engine */
    protected $engine = null;

    /** @var resource $opensslKey */
    protected $opensslKey;

    /** @var RSA $phpseclibKey */
    protected $phpseclibKey;

    /** @var string $privateKeyPem */
    protected $privateKeyPem;

    /** @var RSAPublicKey|null $publicKey */
    protected $publicKey = null;

    protected static $engines = null;

    public function __construct(string $privateKeyPem, string $engine = null)
    {
        if (preg_match('/BEGIN EC PRIVATE KEY/', $privateKeyPem)) {
            throw new InvalidArgumentException('This is EC private key. Use ' . ECPrivateKey::class . ' instead to open this key.');
        }
        if ($engine === null) {
            if (Utils::engineAvailable(Utils::ENGINE_OPENSSL)) {
                $this->openByOpenssl($privateKeyPem);
            } elseif (Utils::engineAvailable(Utils::ENGINE_PHPSECLIB)) {
                $this->openByPhpseclib($privateKeyPem);
            } else {
                throw new Exception('No engine to open this private key');
            }
        } else {
            if (!Utils::engineAvailable($engine)) {
                throw new Exception($engine . ' engine is not available');
            }
            if ($engine === Utils::ENGINE_OPENSSL) {
                $this->openByOpenssl($privateKeyPem);
            } elseif ($engine === Utils::ENGINE_PHPSECLIB) {
                $this->openByPhpseclib($privateKeyPem);
            } else {
                throw new Exception('Invalid $engine: ' . $engine);
            }
        }

        $this->privateKeyPem = $privateKeyPem;
    }

    protected function openByOpenssl(string $privateKeyPem)
    {
        $key = openssl_pkey_get_private($privateKeyPem);
        if (empty($key)) {
            throw new Exception('Opening private key failed (openssl)');
        }
        $details = openssl_pkey_get_details($key);
        if ($details['type'] !== OPENSSL_KEYTYPE_RSA) {
            throw new InvalidArgumentException('This is not an RSA key (openssl)');
        }
        $this->opensslKey = $key;
        $this->engine = Utils::ENGINE_OPENSSL;
    }

    protected function openByPhpseclib(string $privateKeyPem)
    {
        $privKey = new RSA;
        $ok = $privKey->loadKey($privateKeyPem, RSA::PRIVATE_FORMAT_PKCS1);
        if (!$ok) {
            throw new Exception('Opening private key failed (phpseclib)');
        }
        $privKey->setSignatureMode(RSA::SIGNATURE_PKCS1);
        $this->phpseclibKey = $privKey;
        $this->engine = Utils::ENGINE_PHPSECLIB;
    }

    public function engine(): string
    {
        return $this->engine;
    }

    public function getPrivateKeyPem(): string
    {
        return $this->privateKeyPem;
    }

    public function getPublicKey(): PublicKey
    {
        if ($this->publicKey === null) {
            if ($this->engine === Utils::ENGINE_OPENSSL) {
                $details = openssl_pkey_get_details($this->opensslKey);
                $publicKeyPem = $details['key'];
            } elseif ($this->engine === Utils::ENGINE_PHPSECLIB) {
                $publicKeyPem = $this->phpseclibKey->getPublicKey(RSA::PUBLIC_FORMAT_PKCS8);
            } else {
                throw new LogicException;
            }
            $this->publicKey = new RSAPublicKey($publicKeyPem, $this->engine);
        }
        return $this->publicKey;
    }

    /**
     * @param string $data
     * @param string $algo One of: md5, sha1, sha256, sha512
     * @return string
     * @throws Exception
     */
    public function sign(string $data, string $algo): string
    {
        static::checkAlgo($algo);

        if ($this->engine === Utils::ENGINE_OPENSSL) {
            $opensslAlgo = static::opensslAlgo($algo);
            $ok = openssl_sign($data, $signed, $this->opensslKey, $opensslAlgo);
            if ($ok && is_string($signed) && $signed !== '') {
                return $signed;
            } else {
                throw new Exception('openssl_sign() failed');
            }
        }

        if ($this->engine === Utils::ENGINE_PHPSECLIB) {
            $this->phpseclibKey->setHash($algo);
            $result = $this->phpseclibKey->sign($data);
            if (is_string($result) && $result !== '') {
                return $result;
            } else {
                throw new Exception('phpseclib sign() failed');
            }
        }

        throw new LogicException('Unknown engine: ' . $this->engine);
    }

    protected static function checkAlgo(string $algo)
    {
        static $algos = [
            'md5',
            'sha1',
            'sha256',
            'sha384',
            'sha512',
        ];
        if (!in_array($algo, $algos)) {
            new InvalidArgumentException('Invalid $algo: ' . $algo);
        }
    }

    protected static function opensslAlgo(string $algo): int
    {
        if ($algo === 'md5') return OPENSSL_ALGO_MD5;
        if ($algo === 'sha1') return OPENSSL_ALGO_SHA1;
        if ($algo === 'sha256') return OPENSSL_ALGO_SHA256;
        if ($algo === 'sha384') return OPENSSL_ALGO_SHA384;
        if ($algo === 'sha512') return OPENSSL_ALGO_SHA512;
        throw new LogicException;
    }
}