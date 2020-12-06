<?php

namespace pas9x\acme\implementations\crypto;

use Exception;
use InvalidArgumentException;
use LogicException;
use pas9x\acme\contracts\PrivateKey;
use pas9x\acme\contracts\PublicKey;
use pas9x\acme\Utils;

class ECPrivateKey implements PrivateKey
{
    const CURVE_P256 = 'P-256';
    const CURVE_P384 = 'P-384';
    const CURVE_P521 = 'P-521';

    public const CURVE_TO_OPENSSL = [
        self::CURVE_P256 => 'prime256v1',
        self::CURVE_P384 => 'secp384r1',
        self::CURVE_P521 => 'secp521r1',
    ];

    public const OPENSSL_TO_CURVE = [
        'prime256v1' => self::CURVE_P256,
        'secp384r1' => self::CURVE_P384,
        'secp521r1' => self::CURVE_P521,
    ];

    /** @var resource $opensslKey */
    protected $opensslKey;

    /** @var array $opensslDetails */
    protected $opensslDetails;

    /** @var string $curve */
    protected $curve;

    /** @var string $privateKeyPem */
    protected $privateKeyPem;

    /** @var ECPublicKey|null $publicKey */
    protected $publicKey = null;

    protected static $engines = null;

    public function __construct(string $privateKeyPem)
    {
        if (!Utils::engineAvailable(Utils::ENGINE_OPENSSL)) {
            throw new Exception('EC keys requires openssl php module');
        }
        $this->openByOpenssl($privateKeyPem);
        $this->privateKeyPem = $privateKeyPem;
    }

    protected function openByOpenssl(string $privateKeyPem)
    {
        $key = openssl_pkey_get_private($privateKeyPem);
        if (empty($key)) {
            throw new Exception('Opening private key failed (openssl)');
        }
        $this->opensslDetails = openssl_pkey_get_details($key);
        if ($this->opensslDetails['type'] !== OPENSSL_KEYTYPE_EC) {
            throw new Exception('This is not an EC key');
        }
        $opensslCurve = $this->opensslDetails['ec']['curve_name'];
        if (!isset(self::OPENSSL_TO_CURVE[$opensslCurve])) {
            throw new Exception('This public key has unsupported curve: ' . $opensslCurve);
        }
        $this->curve = self::OPENSSL_TO_CURVE[$opensslCurve];
        $this->opensslKey = $key;
        $this->engine = Utils::ENGINE_OPENSSL;
    }

    public function getPrivateKeyPem(): string
    {
        return $this->privateKeyPem;
    }

    public function getPublicKey(): PublicKey
    {
        if ($this->publicKey === null) {
            $details = openssl_pkey_get_details($this->opensslKey);
            $publicKeyPem = $details['key'];
            $this->publicKey = new ECPublicKey($publicKeyPem);
        }
        return $this->publicKey;
    }

    /**
     * @param string $data
     * @param string $algo One of: sha1, sha256, sha384 sha512
     * @return string
     * @throws Exception
     */
    public function sign(string $data, string $algo): string
    {
        static::checkAlgo($algo);

        $opensslAlgo = static::opensslAlgo($algo);
        $ok = openssl_sign($data, $signed, $this->opensslKey, $opensslAlgo);
        if ($ok && is_string($signed) && $signed !== '') {
            return $signed;
        } else {
            throw new Exception('openssl_sign() failed');
        }
    }

    protected static function checkAlgo(string $algo)
    {
        static $algos = [
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
        if ($algo === 'sha1') return OPENSSL_ALGO_SHA1;
        if ($algo === 'sha256') return OPENSSL_ALGO_SHA256;
        if ($algo === 'sha384') return OPENSSL_ALGO_SHA384;
        if ($algo === 'sha512') return OPENSSL_ALGO_SHA512;
        throw new LogicException;
    }
}