<?php

use phpseclib\Crypt\Hash;
use pas9x\acme\Utils;

require_once __DIR__ . '/../includes/bootstrap.php';

if (!defined('CRYPT_HASH_MODE')) {
    define('CRYPT_HASH_MODE', Hash::MODE_INTERNAL);
}

(function () {
    stdout("Check sha256...\n");
    $data = str_repeat('Murka ', rand(1000, 2000));
    $validHash = Utils::sha256($data, Utils::ENGINE_HASH);
    $phpseclibHash = Utils::sha256($data, Utils::ENGINE_PHPSECLIB);
    if ($phpseclibHash !== $validHash) {
        fatal("The phpseclib generated an invalid sha256 hash\n");
    }
    stdout("OK\n");
})();
