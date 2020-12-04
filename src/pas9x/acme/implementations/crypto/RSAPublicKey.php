<?php

namespace pas9x\acme\implementations\crypto;

use Exception;
use LogicException;
use InvalidArgumentException;
use pas9x\acme\Utils;
use phpseclib\Crypt\RSA;
use pas9x\acme\ACME_internals;
use pas9x\acme\contracts\PublicKey;

class RSAPublicKey implements PublicKey
{
    /** @var string $engine */
    protected $engine;

    /** @var string $keyPem */
    protected $keyPem;

    /** @var resource $opensslKey */
    protected $opensslKey;

    /** @var array $opensslDetails */
    protected $opensslDetails;

    /** @var RSA $phpseclibKey */
    protected $phpseclibKey;

    protected static $engines = null;

    public function __construct(string $publicKeyPem, string $engine = null)
    {
        if (preg_match('/BEGIN EC PUBLIC KEY/', $publicKeyPem)) {
            throw new InvalidArgumentException('This is EC public key. Use ' . ECPublicKey::class . ' instead to open this key (1)');
        }
        if ($engine === null) {
            if (Utils::engineAvailable(Utils::ENGINE_OPENSSL)) {
                $this->openByOpenssl($publicKeyPem);
            } elseif (Utils::engineAvailable(Utils::ENGINE_PHPSECLIB)) {
                $this->openByPhpseclib($publicKeyPem);
            } else {
                throw new Exception('No engine to open this public key');
            }
        } else {
            if (!Utils::engineAvailable($engine)) {
                throw new Exception($engine . ' engine is not available');
            }
            if ($engine === Utils::ENGINE_OPENSSL) {
                $this->openByOpenssl($publicKeyPem);
            } elseif ($engine === Utils::ENGINE_PHPSECLIB) {
                $this->openByPhpseclib($publicKeyPem);
            } else {
                throw new InvalidArgumentException('Invalid $engine: ' . $engine);
            }
        }

        $this->keyPem = $publicKeyPem;
    }

    protected function openByOpenssl(string $publicKeyPem)
    {
        $key = openssl_pkey_get_public($publicKeyPem);
        if (empty($key)) {
            throw new Exception('Opening public key failed (openssl)');
        }
        $this->opensslDetails = openssl_pkey_get_details($key);
        if ($this->opensslDetails['type'] !== OPENSSL_KEYTYPE_RSA) {
            throw new InvalidArgumentException('This is not an RSA key (openssl)');
        }
        $this->opensslKey = $key;
        $this->engine = Utils::ENGINE_OPENSSL;

    }

    protected function openByPhpseclib(string $publicKeyPem)
    {
        $pubKey = new RSA;
        $ok = $pubKey->loadKey($publicKeyPem, RSA::PUBLIC_FORMAT_PKCS1);
        if (!$ok) {
            throw new Exception('Opening public key failed (phpseclib)');
        }
        $pubKey->setSignatureMode(RSA::SIGNATURE_PKCS1);
        $this->phpseclibKey = $pubKey;
        $this->engine = Utils::ENGINE_PHPSECLIB;
    }

    public function getPublicKeyPem(): string
    {
        return $this->keyPem;
    }

    /**
     * @param string $data
     * @param string $signature
     * @param string $algo One of: sha1, sha256, sha384 sha512
     * @return bool
     * @throws Exception
     */
    public function verify(string $data, string $signature, string $algo): bool
    {
        static::checkAlgo($algo);

        if ($this->engine === Utils::ENGINE_OPENSSL) {
            $opensslAlgo = static::opensslAlgo($algo);
            $status = openssl_verify($data, $signature, $this->opensslKey, $opensslAlgo);
            if ($status === 1) {
                return true;
            } elseif ($status === 0) {
                return false;
            } elseif ($status === -1) {
                throw new Exception('openssl_verify() failed');
            } else {
                throw new Exception('Unexpected result from openssl_verify()');
            }
        }

        if ($this->engine === Utils::ENGINE_PHPSECLIB) {
            $this->phpseclibKey->setHash($algo);
            $ok = $this->phpseclibKey->verify($data, $signature);
            if (is_bool($ok)) {
                return $ok;
            } else {
                throw new Exception('phpseclib verify() failed');
            }
        }

        throw new LogicException('Unknown engine: ' . $this->engine);
    }

    public function getJWK(): array
    {
        if ($this->engine === Utils::ENGINE_OPENSSL) {
            return [
                'kty' => 'RSA',
                'n' => Utils::b64_urlencode($this->opensslDetails['rsa']['n']),
                'e' => Utils::b64_urlencode($this->opensslDetails['rsa']['e']),
            ];
        }
        if ($this->engine === Utils::ENGINE_PHPSECLIB) {
            return [
                'kty' => 'RSA',
                'n' => Utils:: b64_urlencode($this->phpseclibKey->modulus->toBytes()),
                'e' => Utils::b64_urlencode($this->phpseclibKey->publicExponent->toBytes()),
            ];
        }
        throw new LogicException;
    }

    public function thumbprint(): string
    {
        $jwk = $this->getJWK();
        // We need to create an STRICT json string to get the valid hash
        $result = '{"e":"' . $jwk['e'] . '","kty":"' . $jwk['kty'] . '","n":"' . $jwk['n'] . '"}';
        return $result;
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