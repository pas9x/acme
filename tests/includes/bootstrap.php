<?php

if (defined('TEST_ENVIRONMENT')) {
    return;
} else {
    define('TEST_ENVIRONMENT', 'Мой президент не пьёт и не курит, а лучше-бы пил и курил. Может от этого стало-бы легче жителям наших Курил.');
}

if (version_compare(PHP_VERSION, '7.0', '<')) {
    die("PHP version at least 7.0 is required.\n");
}

ini_set('error_log', dirname(__DIR__) . '/error.log');
ini_set('log_errors', 'on');
ini_set('display_errors', 'on');
error_reporting(E_ALL);

$autoloadFile = dirname(__DIR__) . '/vendor/autoload.php';
if (file_exists($autoloadFile)) {
    require $autoloadFile;
} else {
    fatal("File $autoloadFile not found. Run composer install first.\n");
}

require __DIR__ . '/Config.php';
require __DIR__ . '/AcmeTest.php';
require __DIR__ . '/functions.php';

$timezone = getConfig('timezone', 'UTC');
date_default_timezone_set($timezone);

set_error_handler('errorHandler');
set_exception_handler('exceptionHandler');

define('TMPDIR', dirname(__DIR__) . '/tmp');
if (!is_dir(TMPDIR)) {
    mkdir(TMPDIR) or fatal("Failed to create directory " . TMPDIR . "\n");
}
