<?php

use pas9x\acme\ACME_internals;
use pas9x\acme\implementations\crypto\ECPrivateKeyGenerator;
use pas9x\acme\implementations\crypto\ECPrivateKey;
use pas9x\acme\implementations\crypto\ECPublicKey;
use pas9x\acme\implementations\crypto\ECSigner;
use pas9x\acme\Utils;

require_once __DIR__ . '/../includes/bootstrap.php';

(function () {
    /*
     * Known bug: for some curve+hash phpecc library generates invalid signatures
     * TODO: wait for answering this issue https://github.com/phpecc/phpecc/issues/268
     */
    $bugs = [
        ECPrivateKey::CURVE_P256 => [ECSigner::ALG_ES384, ECSigner::ALG_ES512],
        ECPrivateKey::CURVE_P521 => [ECSigner::ALG_ES512],
    ];

    $curves = [
        ECPrivateKey::CURVE_P256,
        ECPrivateKey::CURVE_P384,
        ECPrivateKey::CURVE_P521,
    ];

    foreach ($curves as $curve) {
        $generator = new ECPrivateKeyGenerator($curve, Utils::ENGINE_ECLIB);

        stdout("Generate $curve private key (eclib)...\n");
        $privateKey = $generator->generatePrivateKey();
        $privateKeyPem = $privateKey->getPrivateKeyPem();
        stdout("OK\n");

        stdout("Export $curve public key (eclib)...\n");
        $publicKey = $privateKey->getPublicKey();
        $publicKeyPem = $publicKey->getPublicKeyPem();
        stdout("OK\n");

        stdout("Load $curve private key (eclib)...\n");
        $privateKey = new ECPrivateKey($privateKeyPem, Utils::ENGINE_ECLIB);
        stdout("OK\n");

        stdout("Load $curve public key (eclib)...\n");
        $publicKey = new ECPublicKey($publicKeyPem, Utils::ENGINE_ECLIB);
        $opensslPublicKey = openssl_pkey_get_public($publicKey->getPublicKeyPem());
        $opensslPubDetails = openssl_pkey_get_details($opensslPublicKey);
        stdout("OK\n");

        $algs = [
            ECSigner::ALG_ES256 => OPENSSL_ALGO_SHA256,
            ECSigner::ALG_ES384 => OPENSSL_ALGO_SHA384,
            ECSigner::ALG_ES512 => OPENSSL_ALGO_SHA512,
        ];
        $data = str_repeat('Murka ', rand(1000, 2000));

        foreach ($algs as $alg => $algOpenssl) {
            if (isset($bugs[$curve]) && in_array($alg, $bugs[$curve])) {
                continue;
            }

            stdout("Create $curve $alg signature (eclib)...\n");
            $signer = new ECSigner($privateKey, $alg);
            $signature = $signer->sign($data);
            stdout("OK\n");

            stdout("Verify $curve $alg signature (eclib)...\n");

            $ok = $signer->verify($data, $signature);
            if ($ok !== true) {
                fatal("Signature verification failed (1)\n");
            }

            $ok = $publicKey->verify($data, $signature, str_replace('ES', 'sha', $alg));
            if ($ok !== true) {
                fatal("Signature verification failed (2)\n");
            }

            $status = openssl_verify($data, $signature, $opensslPublicKey, $algOpenssl);
            if ($status === 1) {
                stdout("OK\n");
            } else {
                stderr("Signature verification failed (3)\n");
                var_dump($status);
                exit(1);
            }

            $jwk = $publicKey->getJWK();
            $x = Utils::b64_urldecode($jwk['x']);
            $y = Utils::b64_urldecode($jwk['y']);
            if ($x !== $opensslPubDetails['ec']['x']) {
                fatal("Signature verification failed (4)\n");
            }
            if ($y !== $opensslPubDetails['ec']['y']) {
                fatal("Signature verification failed (5)\n");
            }
        }
    }
})();
