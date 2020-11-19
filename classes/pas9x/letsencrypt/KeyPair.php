<?php

namespace pas9x\letsencrypt;

use \phpseclib\Crypt\RSA;
use \phpseclib\Crypt\Hash;
use \Exception;

class KeyPair
{
    /** @var RSA $rsa */
    public $rsa;

    /** @var string $privateKeyPem */
    public $privateKeyPem;

    /** @var string $publicKeyPem */
    public $publicKeyPem;

    /**
     * KeyPair constructor.
     * @param RSA|string $privateKey
     * @throws Exception
     */
    public function __construct($privateKey)
    {
        if ($privateKey instanceof RSA) {
            $this->rsa = $privateKey;
        } elseif (is_string($privateKey)) {
            $this->rsa = new RSA;
            $ok = $this->rsa->loadKey($privateKey, RSA::PRIVATE_FORMAT_PKCS1);
            if (!$ok) {
                throw new Exception('Loading private key failed');
            }
        }

        $this->privateKeyPem = $this->rsa->getPrivateKey();
        if (empty($this->privateKeyPem)) {
            throw new Exception('Failed to extract private key');
        }

        $this->publicKeyPem = $this->rsa->getPublicKey(RSA::PUBLIC_FORMAT_PKCS8);
        if (empty($this->publicKeyPem)) {
            throw new Exception('Failed to extract public key from private key');
        }

        $this->rsa->setSignatureMode(RSA::SIGNATURE_PKCS1);
        $this->rsa->setHash('sha256');
    }

    public static function fromFile($privateKeyFile)
    {
        if (!file_exists($privateKeyFile)) {
            throw new Exception("Private key file $privateKeyFile not found");
        }
        $privateKeyText = trim(file_get_contents($privateKeyFile));
        if (empty($privateKeyText)) {
            throw new Exception("File $privateKeyFile is empty");
        }
        return new static($privateKeyText);
    }

    /**
     * @param int $bits
     * @return static
     * @throws Exception
     */
    public static function generate($bits = 2048)
    {
        $rsa = new RSA;
        $keys = $rsa->createKey($bits);
        if (empty($keys['privatekey']) || empty($keys['publickey'])) {
            throw new Exception('Generating private key failed');
        }
        return new static($keys['privatekey']);
    }

    /**
     * https://tools.ietf.org/html/rfc7638
     * @return string
     */
    public function thumbprint()
    {
        $kty = 'RSA';
        $n = LetsEncryptInternals::b64_urlencode($this->rsa->modulus->toBytes());
        $e = LetsEncryptInternals::b64_urlencode($this->rsa->publicExponent->toBytes());
        /* Do not to that. Fucking lets encrypt don't care that valid json can be in arbitrary format. We don't know
        how PHP will encode json in future versions.
        $keyJson = json_encode(compact('e', 'kty', 'n'));
        */
        $keyJson = '{"e":"' . $e . '","kty":"' . $kty . '","n":"' . $n . '"}'; // We have to format strict string to get correct hash
        $result = LetsEncryptInternals::sha256($keyJson);
        return $result;
    }

    public function getJwk()
    {
        return [
            'kty' => 'RSA',
            'n' => LetsEncryptInternals:: b64_urlencode($this->rsa->modulus->toBytes()),
            'e' => LetsEncryptInternals::b64_urlencode($this->rsa->publicExponent->toBytes()),
        ];
    }
}