<?php

namespace pas9x\acme\implementations\crypto;

use Exception;
use LogicException;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Serializer\PrivateKey\DerPrivateKeySerializer;
use Mdanter\Ecc\Serializer\PrivateKey\PemPrivateKeySerializer;
use pas9x\acme\ACME_internals;
use pas9x\acme\contracts\PrivateKey;
use pas9x\acme\contracts\PrivateKeyGenerator;
use pas9x\acme\Utils;

class ECPrivateKeyGenerator implements PrivateKeyGenerator
{
    protected $curve;
    protected $engine;

    public function __construct(string $curve, string $engine = null)
    {
        $this->curve = $curve;
        if ($engine === null) {
            if (Utils::engineAvailable(Utils::ENGINE_OPENSSL)) {
                $this->engine = Utils::ENGINE_OPENSSL;
            } elseif (Utils::engineAvailable(Utils::ENGINE_ECLIB)) {
                $this->engine = Utils::ENGINE_ECLIB;
            } else {
                throw new Exception('No engine to generate EC private key');
            }
        } else {
            if (!Utils::engineAvailable($engine)) {
                throw new Exception($engine . ' engine is not available');
            }
            if ($engine !== Utils::ENGINE_OPENSSL && $engine !== Utils::ENGINE_ECLIB) {
                throw new Exception('Invalid $engine: ' . $engine);
            }
            $this->engine = $engine;
        }
    }

    public function generatePrivateKey(): PrivateKey
    {
        if ($this->engine === Utils::ENGINE_OPENSSL) {
            return $this->generateByOpenssl();
        } elseif ($this->engine === Utils::ENGINE_ECLIB) {
            return $this->generateByEclib();
        } else {
            throw new LogicException;
        }
    }

    protected function generateByOpenssl(): ECPrivateKey
    {
        if (!isset(ECPrivateKey::CURVE_TO_OPENSSL[$this->curve])) {
            throw new Exception('Unsupported curve: ' . $this->curve);
        }
        $config = [
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => ECPrivateKey::CURVE_TO_OPENSSL[$this->curve],
        ];
        $key = openssl_pkey_new($config);
        if (empty($key)) {
            throw new Exception('openssl_pkey_new() failed');
        }
        $ok = openssl_pkey_export($key, $privateKeyPem);
        if (!$ok || !is_string($privateKeyPem) || $privateKeyPem === '') {
            throw new Exception('openssl_pkey_export() failed');
        }
        return new ECPrivateKey($privateKeyPem, $this->engine);
    }

    protected function generateByEclib(): ECPrivateKey
    {
        if ($this->curve === ECPrivateKey::CURVE_P256) {
            $generator = EccFactory::getNistCurves()->generator256();
        } elseif ($this->curve === ECPrivateKey::CURVE_P384) {
            $generator = EccFactory::getNistCurves()->generator384();
        } elseif ($this->curve === ECPrivateKey::CURVE_P521) {
            $generator = EccFactory::getNistCurves()->generator521();
        } else {
            throw new Exception('Unsupported curve: ' . $this->curve);
        }
        $adapter = EccFactory::getAdapter();
        $privkey = $generator->createPrivateKey();
        $derSerializer = new DerPrivateKeySerializer($adapter);
        $pemSerializer = new PemPrivateKeySerializer($derSerializer);
        $pem = $pemSerializer->serialize($privkey);
        return new ECPrivateKey($pem);
    }
}