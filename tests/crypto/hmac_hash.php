<?php

use pas9x\acme\ACME_internals;
use pas9x\acme\implementations\crypto\HMACSigner;
use pas9x\acme\Utils;

require_once __DIR__ . '/../includes/bootstrap.php';

(function () {
    $algs = [
        HMACSigner::ALG_HS256,
        HMACSigner::ALG_HS384,
        HMACSigner::ALG_HS512,
    ];

    foreach ($algs as $alg) {
        $data = str_repeat('Murka ', rand(1000, 2000));
        $key = random_bytes(rand(10, 10000));

        stdout("Check $alg signing (hash)...\n");
        $signer = new HMACSigner($key, $alg, Utils::ENGINE_HASH);
        $signature = $signer->sign($data);
        $ok = $signer->verify($data, $signature);
        if ($ok === true) {
            stdout("OK\n");
        } else {
            var_dump($ok);
            fatal("Signature verification failed.\n");
        }
    }
})();
