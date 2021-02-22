<?php

namespace pas9x\acme;

use Exception;
use LogicException;
use phpseclib\Crypt\Hash;
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
    
    /** @var array|null */
    protected static $engines = null;

    /** @var string|null */
    protected static $tmpDir = null;

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
            return new ECPrivateKey($privateKeyPem);
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

    public static function sha256(string $data, string $engine = null): string
    {
        if ($engine === null) {
            if (static::engineAvailable(static::ENGINE_HASH)) {
                $engine = static::ENGINE_HASH;
            } elseif (static::engineAvailable(static::ENGINE_PHPSECLIB)) {
                $engine = static::ENGINE_PHPSECLIB;
            } else {
                throw new Exception('No engine to make sha256 hash');
            }
        } elseif (!static::engineAvailable($engine)) {
            throw new Exception("Engine `$engine` is not available");
        }

        if ($engine === Utils::ENGINE_HASH) {
            $result = hash('sha256', $data, true);
            return $result;
        }

        if ($engine === Utils::ENGINE_PHPSECLIB) {
            $hasher = new Hash('sha256');
            $result = $hasher->hash($data);
            if (is_string($result) && $result !== '') {
                return $result;
            } else {
                throw new Exception('phpseclib hash() failed');
            }
        }

        throw new LogicException;
    }

    public static function getTmpDir(): string
    {
        if (static::$tmpDir === null) {
            static::$tmpDir = static::detectTmpDir();
            if (static::$tmpDir === null) {
                throw new Exception('Failed to detect temporary directory');
            }
        }
        return static::$tmpDir;
    }

    public static function detectTmpDir(): ?string
    {
        $tmpDir = @sys_get_temp_dir();
        if (!empty($tmpDir) && is_dir($tmpDir) && is_writable($tmpDir)) {
            return $tmpDir;
        }
        $tmpDir = ini_get('upload_tmp_dir');
        if (!empty($tmpDir) && is_dir($tmpDir) && is_writable($tmpDir)) {
            return $tmpDir;
        }
        $tmpDir = ini_get('session.save_path');
        if (!empty($tmpDir) && is_dir($tmpDir) && is_writable($tmpDir)) {
            return $tmpDir;
        }
        $tmpDir = '/tmp';
        if (is_dir($tmpDir) && is_writable($tmpDir)) {
            return $tmpDir;
        }
        return null;
    }

    public static function filePutContents(string $fileName, string $content)
    {
        if (file_exists($fileName)) {
            if (is_dir($fileName)) {
                throw new Exception($fileName . ' is directory');
            }
            if (!is_file($fileName)) {
                throw new Exception($fileName . ' is not a regular file');
            }
            if (!is_writable($fileName)) {
                throw new Exception("File $fileName is not writable");
            }
        }
        $bytesWritten = file_put_contents($fileName, $content);
        if (!is_int($bytesWritten)) {
            throw new Exception('Failed to write file ' . $fileName);
        }
        $contentSize = strlen($content);
        if ($bytesWritten !== $contentSize) {
            throw new Exception("Content size is $contentSize bytes, but only $bytesWritten written");
        }
    }

    public static function randomString(int $length): string
    {
        $result = '';
        for ($j = 0; $j < $length; $j++) {
            switch (mt_rand(0, 2)):
                case 0:
                    $result .= chr(mt_rand(97, 122));
                    break;
                case 1:
                    $result .= chr(mt_rand(65, 90));
                    break;
                case 2:
                    $result .= chr(mt_rand(48, 57));
                    break;
                default:
                    throw new LogicException;
            endswitch;
        }
        return $result;
    }

    public static function normalizeEol(string $text): string
    {
        $result = str_replace("\r\n", "\n", $text);
        $result = str_replace("\r", "\n", $result);
        return $result;
    }

    public static function removeDash(string $pem): string
    {
        $lines = explode("\n", static::normalizeEol($pem));
        foreach ($lines as $index => $line) {
            $trimmed = trim($line);
            if ($trimmed === '') unset($lines[$index]);
        }
        $lines = array_values($lines);
        $linesCount = count($lines);
        if ($linesCount < 3) {
            throw new Exception('Invalid PEM format (1)');
        }
        if (!preg_match('/^\-.+\-$/', $lines[0])) {
            throw new Exception('Invalid PEM format (2)');
        }
        if (!preg_match('/^\-.+\-$/', $lines[$linesCount - 1])) {
            throw new Exception('Invalid PEM format (3)');
        }
        unset($lines[0], $lines[$linesCount - 1]);
        foreach ($lines as $line) {
            if (!preg_match('/^[a-zA-Z0-9\+\/\=]+$/', $line)) {
                throw new Exception('Invalid PEM format (4)');
            }
        }
        return implode('', $lines);
    }

    public static function pemToDer(string $pem): string
    {
        $der_b64 = static::removeDash($pem);
        $result = base64_decode($der_b64);
        return $result;
    }
}