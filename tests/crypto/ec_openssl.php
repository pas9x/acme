<?php

use pas9x\acme\ACME_internals;
use pas9x\acme\implementations\crypto\ECPrivateKeyGenerator;
use pas9x\acme\implementations\crypto\ECPrivateKey;
use pas9x\acme\implementations\crypto\ECPublicKey;
use pas9x\acme\implementations\crypto\ECSigner;
use pas9x\acme\Utils;

require_once __DIR__ . '/../includes/bootstrap.php';

(function () {
    $curves = [
        ECPrivateKey::CURVE_P256,
        ECPrivateKey::CURVE_P384,
        ECPrivateKey::CURVE_P521,
    ];

    foreach ($curves as $curve) {
        $generator = new ECPrivateKeyGenerator($curve, Utils::ENGINE_OPENSSL);

        stdout("Generate $curve private key (openssl)...\n");
        $privateKey = $generator->generatePrivateKey();
        $privateKeyPem = $privateKey->getPrivateKeyPem();
        stdout("OK\n");

        stdout("Export $curve public key (openssl)...\n");
        $publicKey = $privateKey->getPublicKey();
        $publicKeyPem = $publicKey->getPublicKeyPem();
        stdout("OK\n");

        stdout("Load $curve private key (openssl)...\n");
        $privateKey = new ECPrivateKey($privateKeyPem, Utils::ENGINE_OPENSSL);
        stdout("OK\n");

        stdout("Load $curve public key (openssl)...\n");
        $publicKey = new ECPublicKey($publicKeyPem, Utils::ENGINE_OPENSSL);
        stdout($publicKey->thumbprint() . "\n");
        stdout("OK\n");

        $algs = [
            ECSigner::ALG_ES256,
            ECSigner::ALG_ES384,
            ECSigner::ALG_ES512,
        ];
        $data = str_repeat('Murka ', rand(1000, 2000));

        foreach ($algs as $alg) {
            stdout("Create $curve $alg signature (openssl)...\n");
            $signer = new ECSigner($privateKey, $alg);
            $signature = $signer->sign($data);
            stdout("OK\n");

            stdout("Verify $curve $alg signature (openssl)...\n");

            $ok = $signer->verify($data, $signature);
            if ($ok !== true) {
                fatal("Signature verification failed (1)\n");
            }

            $ok = $publicKey->verify($data, $signature, str_replace('ES', 'sha', $alg));
            if ($ok !== true) {
                fatal("Signature verification failed (2)\n");
            }

            stdout("OK\n");
        }
    }
})();
