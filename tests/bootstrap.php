<?php

if (version_compare(PHP_VERSION, '8.1') < 0) {
    die("PHP version at least 8.1 is required.\n");
}

ini_set('error_log', dirname(__DIR__) . '/error.log');
ini_set('log_errors', 'on');
ini_set('display_errors', 'on');
error_reporting(E_ALL);

$autoloadFile = __DIR__ . '/../vendor/autoload.php';
if (file_exists($autoloadFile)) {
    require $autoloadFile;
} else {
    panic("File $autoloadFile not found. Run `composer install` first.\n");
}

define('CSI', "\x1B[");
define('CS_RED', CSI . '31m');
define('CS_GREEN', CSI . '32m');
define('CS_RESET', CSI . '0m');

define('BASEDIR', __DIR__);
require __DIR__ . '/functions.php';

set_error_handler('errorHandler');
set_exception_handler('exceptionHandler');

define('TMPDIR', dirname(__DIR__) . '/tmp');
if (!is_dir(TMPDIR)) {
    mkdir(TMPDIR) or panic("Failed to create directory " . TMPDIR . "\n");
}
