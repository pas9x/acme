<?php

namespace pas9x\acme;

/**
 * @internal
 */
abstract class Utils
{
    /** @var string|null */
    protected static $tmpDir = null;

    public static function jsonDecode(string $json): mixed
    {
        $result = json_decode($json, false);
        $errorCode = json_last_error();
        if ($errorCode !== JSON_ERROR_NONE) {
            $errorMessage = json_last_error_msg();
            throw new \RuntimeException("Failed to decode string as JSON: $errorMessage ($errorCode)");
        }
        return $result;
    }

    public static function jsonEncode($something): string
    {
        $result = json_encode($something, JSON_UNESCAPED_SLASHES);
        $errorCode = json_last_error();
        if ($errorCode !== JSON_ERROR_NONE) {
            $errorMessage = json_last_error_msg();
            throw new \RuntimeException("Failed to encode \$something as JSON: $errorMessage ($errorCode)");
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

    public static function sha256(string $data): string
    {
        $result = hash('sha256', $data, true);
        return $result;
    }

    public static function getTmpDir(): string
    {
        if (static::$tmpDir === null) {
            static::$tmpDir = static::detectTmpDir();
            if (static::$tmpDir === null) {
                throw new \RuntimeException('Failed to detect temporary directory');
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

    public static function filePutContents(string $fileName, string $content): void
    {
        if (file_exists($fileName)) {
            if (is_dir($fileName)) {
                throw new \RuntimeException($fileName . ' is directory');
            }
            if (!is_file($fileName)) {
                throw new \RuntimeException($fileName . ' is not a regular file');
            }
            if (!is_writable($fileName)) {
                throw new \RuntimeException("File $fileName is not writable");
            }
        }
        $bytesWritten = file_put_contents($fileName, $content);
        if (!is_int($bytesWritten)) {
            throw new \RuntimeException('Failed to write file ' . $fileName);
        }
        $contentSize = strlen($content);
        if ($bytesWritten !== $contentSize) {
            throw new \RuntimeException("Content size is $contentSize bytes, but only $bytesWritten written");
        }
    }

    // TODO: use random_bytes()
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
                    throw new \LogicException;
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
            throw new \RuntimeException('Invalid PEM format (1)');
        }
        if (!preg_match('/^\-.+\-$/', $lines[0])) {
            throw new \RuntimeException('Invalid PEM format (2)');
        }
        if (!preg_match('/^\-.+\-$/', $lines[$linesCount - 1])) {
            throw new \RuntimeException('Invalid PEM format (3)');
        }
        unset($lines[0], $lines[$linesCount - 1]);
        foreach ($lines as $line) {
            if (!preg_match('/^[a-zA-Z0-9\+\/\=]+$/', $line)) {
                throw new \RuntimeException('Invalid PEM format (4)');
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

    public static function gettype($value): string
    {
        if (is_object($value)) {
            return 'object (' . get_class($value) . ')';
        } else {
            return gettype($value);
        }
    }

    public static function isNumericArray($arr, bool $strict = true)
    {
        if (!is_array($arr)) {
            return false;
        }

        if ($strict) {
            $count = count($arr);
            for ($j = 0; $j < $count; $j++) {
                if (!array_key_exists($j, $arr)) {
                    return false;
                }
            }
            return true;
        } else {
            foreach ($arr as $key => $value) {
                if (!is_int($key)) {
                    return false;
                }
            }
            return true;
        }
    }
}