<?php

function stdout($text)
{
    $text = strval($text);
    $len = strlen($text);
    $bytesWrited = @fwrite(STDOUT, $text);
    return ($bytesWrited === $len);
}

function stderr($text)
{
    $text = strval($text);
    $len = strlen($text);
    $bytesWrited = @fwrite(STDERR, $text);
    return ($bytesWrited === $len);
}

function fatal($text, $exitCode = 1)
{
    stderr($text);
    exit(intval($exitCode));
}

/**
 * @param null|callable $newHandler
 * @return null|callable
 */
function testErrorHandler($newHandler = null)
{
    static $errorHandler = null;
    if (func_num_args() > 0) {
        $errorHandler = $newHandler;
    }
    return $errorHandler;
}

function getConstName($errorCode)
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
        if (defined('E_STRICT')) $names[E_STRICT] = 'E_STRICT';
        if (defined('E_RECOVERABLE_ERROR')) $names[E_RECOVERABLE_ERROR] = 'E_RECOVERABLE_ERROR';
        if (defined('E_DEPRECATED')) $names[E_DEPRECATED] = 'E_DEPRECATED';
        if (defined('E_USER_DEPRECATED')) $names[E_USER_DEPRECATED] = 'E_USER_DEPRECATED';
        if (defined('E_ALL')) $names[E_ALL] = 'E_ALL';
    }
    return isset($names[$errorCode]) ? $names[$errorCode] : null;
}

function baseErrorHandler($errno, $errstr, $errfile, $errline)
{
    $testHandler = testErrorHandler();
    if (is_callable($testHandler)) {
        $testHandler($errno, $errstr, $errfile, $errline);
    } else {
        if (error_reporting() === 0) {
            return;
        }
        if ($errno === E_DEPRECATED) {
            return;
        }
        $constName = getConstName($errno);
        $errorType = is_null($constName) ? "Error $errno" : $constName;
        $message = "$errorType: $errstr\n";
        $message .= "File: $errfile:$errline\n";
        stderr('[' . date('H:i:s') . '] ' .  $message);
        logError($message);
    }
}

/**
 * @param Exception|Throwable $exception
 */
function exceptionHandler($exception)
{
    $message = 'Uncaught ' .  trim($exception->__toString()) . "\n";
    logError($message);
    fatal($message);
}

function logError($errorMessage, $details = null)
{
    $fh = null;
    $logFile = __DIR__ . '/../error.log';
    if ($fh === null) {
        $fh = fopen($logFile, 'a');
        if (!is_resource($fh)) {
            fatal("Failed to open $logFile.\n");
        }
    }
    $logEntry = '[' . date('d.m.Y H:i:s') . ' ' . trim($errorMessage) . "\n";
    if ($details !== null) {
        $logEntry .= 'Details: ' . trim(print_r($details, true)) . "\n";
    }
    $logEntry .= "\n";
    $bytesWrited = fwrite($fh, $logEntry);
    if ($bytesWrited !== strlen($logEntry)) {
        fatal("Failed to write $logFile.\n");
    }
}

function arrayPath($path, $array, $delimiter = '.')
{
    $levels = explode($delimiter, $path);
    $levelsCount = count($levels);
    $currentThread = $array;
    $pastLevels = [];
    for ($levelNumber = 0; $levelNumber < $levelsCount; $levelNumber++) {
        $level = $levels[$levelNumber];
        $pastLevels[] = $level;
        if (array_key_exists($level, $currentThread)) {
            $currentThread = $currentThread[$level];
            if (!is_array($currentThread)) {
                if (isset($levels[$levelNumber + 1])) {
                    $strPastLevels = implode($delimiter, $pastLevels);
                    throw new ArrayPathNotFound("Node $strPastLevels is not an array", $strPastLevels);
                }
            }
        } else {
            $strPastLevels = implode($delimiter, $pastLevels);
            $e = new ArrayPathNotFound("Array node $strPastLevels not found", $strPastLevels);
            $e->notfound = $path;
            throw $e;
        }
    }
    return $currentThread;
}

function fullConfig(array $newConfig = null)
{
    static $config = null;
    if ($newConfig !== null) {
        $config = $newConfig;
    }
    return $config;
}

function getConfig($path, $defaultValue = null)
{
    $config = fullConfig();
    try {
        $value = arrayPath($path, $config);
        return $value;
    } catch (ArrayPathNotFound $e) {
        if (func_num_args() > 1) {
            return $defaultValue;
        } else {
            throw new Exception("Config parameter $path not found");
        }
    }
}
