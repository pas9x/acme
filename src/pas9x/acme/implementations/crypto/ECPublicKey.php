<?php

namespace pas9x\acme\implementations\crypto;

use Exception;
use LogicException;
use InvalidArgumentException;
use pas9x\acme\contracts\PublicKey;
use pas9x\acme\Utils;

class ECPublicKey implements PublicKey
{
    /** @var string $keyPem */
    protected $keyPem;

    /** @var resource $opensslKey */
    protected $opensslKey;

    /** @var array $opensslDetails */
    protected $opensslDetails;

    /** @var string $curve */
    protected $curve;

    public function __construct(string $publicKeyPem)
    {
        if (!Utils::engineAvailable(Utils::ENGINE_OPENSSL)) {
            throw new Exception('EC keys requires openssl php module');
        }
        $this->openByOpenssl($publicKeyPem);
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

    public function getJWK(): array
    {
        return [
            'kty' => 'EC',
            'crv' => $this->curve,
            'x' => Utils::b64_urlencode($this->opensslDetails['ec']['x']),
            'y' => Utils::b64_urlencode($this->opensslDetails['ec']['y']),
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