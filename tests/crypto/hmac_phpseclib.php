<?php

use pas9x\acme\Utils;
use phpseclib\Crypt\Hash;
use pas9x\acme\ACME_internals;
use pas9x\acme\implementations\crypto\HMACSigner;

require_once __DIR__ . '/../includes/bootstrap.php';

define('CRYPT_HASH_MODE', Hash::MODE_INTERNAL);

(function () {
    $algs = [
        HMACSigner::ALG_HS256,
        HMACSigner::ALG_HS384,
        HMACSigner::ALG_HS512,
    ];

    foreach ($algs as $alg) {
        $data = str_repeat('Murka ', rand(1000, 2000));
        $key = random_bytes(rand(10, 2000));

        stdout("Check $alg signing (phpsrclib)...\n");
        $signer = new HMACSigner($key, $alg, Utils::ENGINE_PHPSECLIB);
        $signature = $signer->sign($data);
        $ok = $signer->verify($data, $signature);
        if ($ok === true) {
            stdout("OK\n");
        } else {
            var_dump($ok);
            fatal("Signature verification failed (1)\n");
        }

        $hashSignature = hash_hmac(str_replace('HS', 'sha', $alg), $data, $key, true);
        if ($signature !== $hashSignature) {
            stdout('Valid signature:  ' . unpack('H*', $hashSignature)[1] . "\n");
            stdout('Actual signature: ' . unpack('H*', $signature)[1] . "\n");
            fatal("Signature verification failed (2)\n");
        }
    }
})();
