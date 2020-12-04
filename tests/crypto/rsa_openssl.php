<?php

use pas9x\acme\ACME_internals;
use pas9x\acme\implementations\crypto\RSAPrivateKeyGenerator;
use pas9x\acme\implementations\crypto\RSAPrivateKey;
use pas9x\acme\implementations\crypto\RSAPublicKey;
use pas9x\acme\implementations\crypto\RSASigner;
use pas9x\acme\Utils;

require_once __DIR__ . '/../includes/bootstrap.php';

(function () {
    $generator = new RSAPrivateKeyGenerator(4096, Utils::ENGINE_OPENSSL);

    stdout("Generate private key (openssl)...\n");
    $privateKey = $generator->generatePrivateKey();
    $privateKeyPem = $privateKey->getPrivateKeyPem();
    stdout("OK\n");

    stdout("Export public key (openssl)...\n");
    $publicKey = $privateKey->getPublicKey();
    $publicKeyPem = $publicKey->getPublicKeyPem();
    stdout("OK\n");

    stdout("Load private key (openssl)...\n");
    $privateKey = new RSAPrivateKey($privateKeyPem, Utils::ENGINE_OPENSSL);
    stdout("OK\n");

    stdout("Load public key (openssl)...\n");
    $publicKey = new RSAPublicKey($publicKeyPem, Utils::ENGINE_OPENSSL);
    stdout("OK\n");

    $algs = [
        RSASigner::ALG_RS256 => OPENSSL_ALGO_SHA256,
        RSASigner::ALG_RS384 => OPENSSL_ALGO_SHA384,
        RSASigner::ALG_RS512 => OPENSSL_ALGO_SHA512,
    ];
    $data = str_repeat('Murka ', rand(1000, 2000));
    foreach ($algs as $alg => $algOpenssl) {
        stdout("Create $alg signature (openssl)...\n");
        $signer = new RSASigner($privateKey, $alg);
        $signature = $signer->sign($data);
        stdout("OK\n");

        stdout("Verify $alg signature (openssl)...\n");

        $ok = $signer->verify($data, $signature);
        if ($ok !== true) {
            fatal("Signature verification failed (1)\n");
        }

        $ok = $publicKey->verify($data, $signature, str_replace('RS', 'sha', $alg));
        if ($ok !== true) {
            fatal("Signature verification failed (2)\n");
        }

        $opensslPublicKey = openssl_pkey_get_public($publicKey->getPublicKeyPem());
        $status = openssl_verify($data, $signature, $opensslPublicKey, $algOpenssl);
        if ($status === 1) {
            stdout("OK\n");
        } else {
            stderr("Signature verification failed (3)\n");
            var_dump($status);
            exit(1);
        }
    }
})();
