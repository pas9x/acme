<?php

if (defined('TESTS_BOOTSTRAP')) {
    return;
} else {
    define('TESTS_BOOTSTRAP', true);
}

if (version_compare(PHP_VERSION, '5.4', '<')) {
    die("PHP version at least 5.4 is required.\n");
}

ini_set('error_log', dirname(__DIR__) . '/error.log');
ini_set('log_errors', 'on');
ini_set('display_errors', 'on');
error_reporting(E_ALL);

$autoloadFile = dirname(dirname(__DIR__)) . '/vendor/autoload.php';
if (file_exists($autoloadFile)) {
    require $autoloadFile;
} else {
    fatal("File $autoloadFile not found. Run composer install first.\n");
}

require __DIR__ . '/functions.php';
require __DIR__ . '/classes.php';
require __DIR__ . '/test_wrap.php';
$configFile = dirname(__DIR__) . '/config.php';
if (file_exists($configFile)) {
    $config = require $configFile;
    fullConfig($config);
} else {
    fatal("File $configFile not found. First make it using config.example.php template.\n");
}

$timezone = getConfig('timezone', 'UTC');
date_default_timezone_set($timezone);

set_error_handler('baseErrorHandler');
set_exception_handler('exceptionHandler');
