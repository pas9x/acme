<?php

namespace pas9x\acme\implementations\crypto;

use Exception;
use LogicException;
use InvalidArgumentException;

use Mdanter\Ecc\Crypto\Signature\SignHasher;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Crypto\Key\PublicKeyInterface;
use Mdanter\Ecc\Curves\NamedCurveFp;
use Mdanter\Ecc\Crypto\Signature\Signer;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\PemPublicKeySerializer;
use Mdanter\Ecc\Serializer\Point\UncompressedPointSerializer;
use Mdanter\Ecc\Serializer\Signature\DerSignatureSerializer;

use pas9x\acme\ACME_internals;
use pas9x\acme\contracts\PublicKey;
use pas9x\acme\Utils;

class ECPublicKey implements PublicKey
{
    /** @var string $engine */
    protected $engine;

    /** @var string $keyPem */
    protected $keyPem;

    /** @var resource $opensslKey */
    protected $opensslKey;

    /** @var array $opensslDetails */
    protected $opensslDetails;

    /** @var string $curve */
    protected $curve;

    /** @var PublicKeyInterface $eclibKey */
    protected $eclibKey;

    /** @var string $eclibCurve */
    protected $eclibCurve;

    protected static $engines = null;

    public function __construct(string $publicKeyPem, string $engine = null)
    {
        if ($engine === null) {
            if (Utils::engineAvailable(Utils::ENGINE_OPENSSL)) {
                $this->openByOpenssl($publicKeyPem);
            } elseif (Utils::engineAvailable(Utils::ENGINE_ECLIB)) {
                $this->openByEclib($publicKeyPem);
            } else {
                throw new Exception('No engine to open this public key');
            }
        } else {
            if (!Utils::engineAvailable($engine)) {
                throw new Exception($engine . ' engine is not available');
            }
            if ($engine === Utils::ENGINE_OPENSSL) {
                $this->openByOpenssl($publicKeyPem);
            } elseif ($engine === Utils::ENGINE_ECLIB) {
                $this->openByEclib($publicKeyPem);
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
        if ($this->opensslDetails['type'] !== OPENSSL_KEYTYPE_EC) {
            throw new InvalidArgumentException('This is not an EC key (openssl)');
        }
        $opensslCurve = $this->opensslDetails['ec']['curve_name'];
        if (!isset(ECPrivateKey::OPENSSL_TO_CURVE[$opensslCurve])) {
            throw new Exception('This public key has unsupported curve: ' . $opensslCurve);
        }
        $this->curve = ECPrivateKey::OPENSSL_TO_CURVE[$opensslCurve];
        $this->opensslKey = $key;
        $this->engine = Utils::ENGINE_OPENSSL;

    }

    protected function openByEclib(string $publicKeyPem)
    {
        $adapter = EccFactory::getAdapter();
        $derSerializer = new DerPublicKeySerializer($adapter);
        $pemSerializer = new PemPublicKeySerializer($derSerializer);
        $this->eclibKey = $pemSerializer->parse($publicKeyPem);
        if (!($this->eclibKey instanceof PublicKeyInterface)) {
            throw new Exception('Opening public key failed (eclib)');
        }

        $curve = $this->eclibKey->getPoint()->getCurve();
        if ($curve instanceof NamedCurveFp) {
            $name = $curve->getName();
            if (isset(ECPrivateKey::ECLIB_TO_CURVE[$name])) {
                $this->curve = ECPrivateKey::ECLIB_TO_CURVE[$name];
            } else {
                throw new Exception('This public key has unsupported curve: ' . $name);
            }
        } else {
            throw new LogicException('Failed to detect curve');
        }

        $this->engine = Utils::ENGINE_ECLIB;
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

        if ($this->engine === Utils::ENGINE_ECLIB) {
            $adapter = EccFactory::getAdapter();
            $sigSerializer = new DerSignatureSerializer();
            $signatureParsed = $sigSerializer->parse($signature);
            $hasher = new SignHasher($algo);
            $generator = EccFactory::getNistCurves()->generator384();
            $hash = $hasher->makeHash($data, $generator);
            $signer = new Signer($adapter);
            $ok = $signer->verify($this->eclibKey, $signatureParsed, $hash);
            if (is_bool($ok)) {
                return $ok;
            } else {
                throw new Exception('eclib verify() failed');
            }
        }

        throw new LogicException;
    }

    public function getJWK(): array
    {
        if ($this->engine === Utils::ENGINE_OPENSSL) {
            return [
                'kty' => 'EC',
                'crv' => $this->curve,
                'x' => Utils::b64_urlencode($this->opensslDetails['ec']['x']),
                'y' => Utils::b64_urlencode($this->opensslDetails['ec']['y']),
            ];
        }
        if ($this->engine === Utils::ENGINE_ECLIB) {
            $point = $this->getXY();
            return [
                'kty' => 'EC',
                'crv' => $this->curve,
                'x' => Utils::b64_urlencode($point['x']),
                'y' => Utils::b64_urlencode($point['y']),
            ];
        }
        throw new LogicException;
    }

    protected function getXY(): array
    {
        $serializer = new UncompressedPointSerializer;
        $point = $serializer->serialize($this->eclibKey->getPoint());
        if (substr($point, 0, 2) !== '04') {
            throw new LogicException('Unexpected UncompressedPointSerializer->serialize() result (1)');
        }
        $point = preg_replace('/^04/', '', $point);
        $len = strlen($point);
        if (($len % 4) !== 0) {
            throw new LogicException('Unexpected UncompressedPointSerializer->serialize() result (2)');
        }
        $x = substr($point, 0, $len / 2);
        $y = substr($point, $len / 2);
        return [
            'x' => pack('H*', $x),
            'y' => pack('H*', $y),
        ];
    }

    public function thumbprint(): string
    {
        $jwk = $this->getJWK();
        // We need to create an STRICT json string to get the valid hash
        $result = '{"crv":"' . $jwk['crv'] . '","kty":"' . $jwk['kty'] . '","x":"' . $jwk['x'] . '","y":"' . $jwk['y'] . '"}';
        return $result;
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