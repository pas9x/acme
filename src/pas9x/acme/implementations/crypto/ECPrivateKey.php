<?php

namespace pas9x\acme\implementations\crypto;

use Exception;
use InvalidArgumentException;
use LogicException;

use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Serializer\PrivateKey\DerPrivateKeySerializer;
use Mdanter\Ecc\Serializer\PrivateKey\PemPrivateKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\PemPublicKeySerializer;
use Mdanter\Ecc\Random\RandomGeneratorFactory;
use Mdanter\Ecc\Crypto\Key\PrivateKeyInterface;
use Mdanter\Ecc\Crypto\Signature\SignHasher;
use Mdanter\Ecc\Crypto\Signature\Signer;
use Mdanter\Ecc\Crypto\Signature\SignatureInterface;
use Mdanter\Ecc\Serializer\Signature\DerSignatureSerializer;
use Mdanter\Ecc\Curves\SecgCurve;
use Mdanter\Ecc\Curves\NistCurve;
use Mdanter\Ecc\Curves\NamedCurveFp;

use pas9x\acme\ACME_internals;
use pas9x\acme\contracts\PrivateKey;
use pas9x\acme\contracts\PublicKey;
use pas9x\acme\Utils;

class ECPrivateKey implements PrivateKey
{
    const CURVE_P256 = 'P-256';
    const CURVE_P384 = 'P-384';
    const CURVE_P521 = 'P-521';

    const CURVE_TO_OPENSSL = [
        self::CURVE_P256 => 'prime256v1',
        self::CURVE_P384 => 'secp384r1',
        self::CURVE_P521 => 'secp521r1',
    ];

    const OPENSSL_TO_CURVE = [
        'prime256v1' => self::CURVE_P256,
        'secp384r1' => self::CURVE_P384,
        'secp521r1' => self::CURVE_P521,
    ];

    const ECLIB_TO_CURVE = [
        SecgCurve::NAME_SECP_256R1 => self::CURVE_P256,
        SecgCurve::NAME_SECP_384R1 => self::CURVE_P384,
        NistCurve::NAME_P521 => self::CURVE_P521,
    ];

    /** @var string $engine */
    protected $engine = null;

    /** @var resource $opensslKey */
    protected $opensslKey;

    /** @var array $opensslDetails */
    protected $opensslDetails;

    /** @var string $curve */
    protected $curve;

    /** @var PrivateKeyInterface $eclibKey */
    protected $eclibKey;

    /** @var string $privateKeyPem */
    protected $privateKeyPem;

    /** @var ECPublicKey|null $publicKey */
    protected $publicKey = null;

    protected static $engines = null;

    public function __construct(string $privateKeyPem, string $engine = null)
    {
        if ($engine === null) {
            if (Utils::engineAvailable(Utils::ENGINE_OPENSSL)) {
                $this->openByOpenssl($privateKeyPem);
            } elseif (Utils::engineAvailable(Utils::ENGINE_ECLIB)) {
                $this->openByEclib($privateKeyPem);
            } else {
                throw new Exception('No engine to open this private key');
            }
        } else {
            if (!Utils::engineAvailable($engine)) {
                throw new Exception($engine . ' engine is not available');
            }
            if ($engine === Utils::ENGINE_OPENSSL) {
                $this->openByOpenssl($privateKeyPem);
            } elseif ($engine === Utils::ENGINE_ECLIB) {
                $this->openByEclib($privateKeyPem);
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

    protected function openByEclib(string $privateKeyPem)
    {
        $adapter = EccFactory::getAdapter();
        $derSerializer = new DerPrivateKeySerializer($adapter);
        $pemSerializer = new PemPrivateKeySerializer($derSerializer);
        $this->eclibKey = $pemSerializer->parse($privateKeyPem);
        if (!($this->eclibKey instanceof PrivateKeyInterface)) {
            throw new Exception('Opening private key failed (eclib)');
        }

        $curve = $this->eclibKey->getPoint()->getCurve();
        if ($curve instanceof NamedCurveFp) {
            $name = $curve->getName();
            if (isset(self::ECLIB_TO_CURVE[$name])) {
                $this->curve = self::ECLIB_TO_CURVE[$name];
            } else {
                throw new Exception('This public key has unsupported curve: ' . $name);
            }
        } else {
            throw new LogicException('Failed to detect curve');
        }

        $this->engine = Utils::ENGINE_ECLIB;
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
            } elseif ($this->engine === Utils::ENGINE_ECLIB) {
                $pubkey = $this->eclibKey->getPublicKey();
                $adapter = EccFactory::getAdapter();
                $derSerializer = new DerPublicKeySerializer($adapter);
                $pemSerializer = new PemPublicKeySerializer($derSerializer);
                $publicKeyPem = $pemSerializer->serialize($pubkey);
            } else {
                throw new LogicException;
            }
            $this->publicKey = new ECPublicKey($publicKeyPem, $this->engine);
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

        if ($this->engine === Utils::ENGINE_OPENSSL) {
            $opensslAlgo = static::opensslAlgo($algo);
            $ok = openssl_sign($data, $signed, $this->opensslKey, $opensslAlgo);
            if ($ok && is_string($signed) && $signed !== '') {
                return $signed;
            } else {
                throw new Exception('openssl_sign() failed');
            }
        }

        if ($this->engine === Utils::ENGINE_ECLIB) {
            $adapter = EccFactory::getAdapter();
            $generator = EccFactory::getNistCurves()->generator384();

            $hasher = new SignHasher($algo, $adapter);
            $hash = $hasher->makeHash($data, $generator);

            $useDerandomizedSignatures = false;
            if ($useDerandomizedSignatures) {
                $random = RandomGeneratorFactory::getHmacRandomGenerator($this->eclibKey, $hash, $algo);
            } else {
                $random = RandomGeneratorFactory::getRandomGenerator();
            }
            $randomK = $random->generate($generator->getOrder());

            $signer = new Signer($adapter);
            $signature = $signer->sign($this->eclibKey, $hash, $randomK);
            if (!($signature instanceof SignatureInterface)) {
                throw new Exception('eclib sign() failed');
            }
            $serializer = new DerSignatureSerializer;
            $result = $serializer->serialize($signature);
            if (is_string($result) && $result !== '') {
                return $result;
            } else {
                throw new Exception('eclib serialize() failed');
            }
        }

        throw new LogicException('Unknown engine: ' . $this->engine);
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