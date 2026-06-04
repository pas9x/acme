<?php

use test\config\Config;
use test\Args;

function stdout(string $text): bool
{
    $len = strlen($text);
    $bytesWrited = @fwrite(STDOUT, $text);
    return ($bytesWrited === $len);
}

function stderr(string $text): bool
{
    $len = strlen($text);
    $bytesWrited = @fwrite(STDERR, $text);
    return ($bytesWrited === $len);
}

function readln(?string $prompt = null): string
{
    if ($prompt !== null && $prompt !== '') {
        stdout($prompt);
    }
    return fgets(STDIN);
}

function panic(string $text, int $exitCode = 1): never
{
    stderr($text);
    exit($exitCode);
}

function getConstName(int $errorCode): ?string
{
    static $names = null;
    if ($names === null) {
        $names = [];
        if (defined('E_ERROR')) $names[E_ERROR] = 'E_ERROR';
        if (defined('E_WARNING')) $names[E_WARNING] = 'E_WARNING';
        if (defined('E_PARSE')) $names[E_PARSE] = 'E_PARSE';
        if (defined('E_NOTICE')) $names[E_NOTICE] = 'E_NOTICE';
        if (defined('E_CORE_ERROR')) $names[E_CORE_ERROR] = 'E_CORE_ERROR';
        if (defined('E_CORE_WARNING')) $names[E_CORE_WARNING] = 'E_CORE_WARNING';
        if (defined('E_COMPILE_ERROR')) $names[E_COMPILE_ERROR] = 'E_COMPILE_ERROR';
        if (defined('E_COMPILE_WARNING')) $names[E_COMPILE_WARNING] = 'E_COMPILE_WARNING';
        if (defined('E_USER_ERROR')) $names[E_USER_ERROR] = 'E_USER_ERROR';
        if (defined('E_USER_WARNING')) $names[E_USER_WARNING] = 'E_USER_WARNING';
        if (defined('E_USER_NOTICE')) $names[E_USER_NOTICE] = 'E_USER_NOTICE';
        if (@defined('E_STRICT')) $names[@E_STRICT] = 'E_STRICT';
        if (defined('E_RECOVERABLE_ERROR')) $names[E_RECOVERABLE_ERROR] = 'E_RECOVERABLE_ERROR';
        if (defined('E_DEPRECATED')) $names[E_DEPRECATED] = 'E_DEPRECATED';
        if (defined('E_USER_DEPRECATED')) $names[E_USER_DEPRECATED] = 'E_USER_DEPRECATED';
        if (defined('E_ALL')) $names[E_ALL] = 'E_ALL';
    }
    return $names[$errorCode] ?? null;
}

function errorHandler(int $errno, string $errstr, string $errfile, int $errline)
{
    if (error_reporting() === 0) {
        return;
    }
    /*
    if ($errno === E_DEPRECATED) {
        return;
    }
    */
    $constName = getConstName($errno);
    $errorType = is_null($constName) ? "Error $errno" : $constName;
    $message = "$errorType: $errstr\n";
    $message .= "File: $errfile:$errline\n";
    stderr('[' . date('H:i:s') . '] ' .  $message);
    logError($message);
}

function exceptionHandler(Throwable $exception)
{
    $message = 'Uncaught ' .  trim($exception->__toString()) . "\n";
    logError($message);
    panic($message);
}

function logError(string $errorMessage, $details = null): void
{
    static $fh = null;
    $logFile = __DIR__ . '/../error.log';
    if ($fh === null) {
        $fh = fopen($logFile, 'a');
        if (!is_resource($fh)) {
            panic("Failed to open $logFile.\n");
        }
    }
    $logEntry = '[' . date('d.m.Y H:i:s') . ' ' . trim($errorMessage) . "\n";
    if ($details !== null) {
        $logEntry .= 'Details: ' . trim(print_r($details, true)) . "\n";
    }
    $logEntry .= "\n";
    $bytesWrited = fwrite($fh, $logEntry);
    if ($bytesWrited !== strlen($logEntry)) {
        panic("Failed to write $logFile.\n");
    }
}

function config(): Config
{
    static $config = null;
    if ($config === null) {
        $file = __DIR__ . '/config.php';
        if (!file_exists($file)) {
            panic("File $file not found. Create it first from config.example.php.\n");
        }
        $config = Config::loadFromFile($file);
    }
    return $config;
}

function args(): Args
{
    static $args = null;
    if ($args === null) {
        $args = new Args;
    }
    return $args;
}

function runScript(string $scriptFile): void
{
    static $php = null;
    if ($php === null) {
        if (!defined('PHP_BINARY')) {
            throw new \RuntimeException('No PHP_BINARY constant');
        }
        if (!file_exists(PHP_BINARY)) {
            throw new \RuntimeException(PHP_BINARY . ' does not exist');
        }
        if (!is_file(PHP_BINARY)) {
            throw new \RuntimeException(PHP_BINARY . ' not a file');
        }
        if (!is_executable(PHP_BINARY)) {
            throw new \RuntimeException(PHP_BINARY . ' not executable');
        }
        $php = PHP_BINARY;
    }
    system($php . ' ' . escapeshellarg($scriptFile));
}
