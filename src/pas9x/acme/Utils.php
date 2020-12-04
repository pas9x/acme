<?php

namespace pas9x\acme;

use Exception;
use LogicException;
use pas9x\acme\contracts\PrivateKey;
use pas9x\acme\contracts\Signer;
use pas9x\acme\implementations\crypto\ECPrivateKey;
use pas9x\acme\implementations\crypto\ECSigner;
use pas9x\acme\implementations\crypto\RSAPrivateKey;
use pas9x\acme\implementations\crypto\RSASigner;

abstract class Utils
{
    const ENGINE_OPENSSL = 'openssl';
    const ENGINE_PHPSECLIB = 'phpseclib';
    const ENGINE_HASH = 'hash';
    const ENGINE_ECLIB = 'eclib';
    
    /** @var array|null */
    protected static $engines = null;

    /**
     * @param bool $useCache
     * @return string[]
     */
    public static function availableEngines(bool $useCache = true): array
    {
        if (!$useCache || self::$engines === null) {
            self::$engines = [];
            if (extension_loaded('openssl')) {
                self::$engines[] = self::ENGINE_OPENSSL;
            }
            if (class_exists(\phpseclib\Crypt\RSA::class)) {
                self::$engines[] = self::ENGINE_PHPSECLIB;
            }
            if (extension_loaded('gmp') && class_exists(\Mdanter\Ecc\EccFactory::class)) {
                self::$engines[] = self::ENGINE_ECLIB;
            }
            if (extension_loaded('hash')) {
                self::$engines[] = self::ENGINE_HASH;
            }
        }
        return self::$engines;
    }

    public static function autodetectSigner(PrivateKey $privateKey): Signer
    {
        if ($privateKey instanceof RSAPrivateKey) {
            return new RSASigner($privateKey, RSASigner::ALG_RS256);
        } elseif ($privateKey instanceof ECPrivateKey) {
            return new ECSigner($privateKey, ECSigner::ALG_ES256);
        } else {
            throw new LogicException('Failed to autodetect signer for ' . get_class($privateKey) . ' private key. You must specify signer explicitly.');
        }
    }

    public static function loadPrivateKey(string $privateKeyPem, string $engine = null): PrivateKey
    {
        if (preg_match('/EC PRIVATE KEY/', $privateKeyPem)) {
            return new ECPrivateKey($privateKeyPem, $engine);
        } else {
            return new RSAPrivateKey($privateKeyPem, $engine);
        }
    }

    public static function engineAvailable(string $engine, bool $useCache = true): bool
    {
        $engines = Utils::availableEngines($useCache);
        return in_array($engine, $engines);
    }

    public static function jsonDecode(string $json)
    {
        $result = json_decode($json, true);
        $errorCode = json_last_error();
        if ($errorCode !== JSON_ERROR_NONE) {
            $errorMessage = json_last_error_msg();
            throw new Exception("Failed to decode string as JSON: $errorMessage ($errorCode)");
        }
        return $result;
    }

    public static function jsonEncode($something): string
    {
        $result = json_encode($something, JSON_UNESCAPED_SLASHES);
        $errorCode = json_last_error();
        if ($errorCode !== JSON_ERROR_NONE) {
            $errorMessage = json_last_error_msg();
            throw new Exception("Failed to encode \$something as JSON: $errorMessage ($errorCode)");
        }
        return $result;
    }

    public static function b64_urlencode(string $input): string
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    public static function b64_urldecode(string $input): string
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }
}