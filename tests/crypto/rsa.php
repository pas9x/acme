<?php

use pas9x\acme\crypto\PrivateKeyRSA;
use pas9x\acme\crypto\PublicKeyRSA;
use pas9x\acme\enums\SignatureAlgorithm;
use test\TestFailedException;
use test\OpenSSL;

require_once __DIR__ . '/../bootstrap.php';

(function () {
    stdout("Generate private key...\n");
    $privateKey = PrivateKeyRSA::generate(2048);
    $privateKeyPem = $privateKey->getPrivateKeyPem();
    if (!str_contains($privateKeyPem, 'BEGIN PRIVATE KEY')) {
        throw new TestFailedException('Exporting private key failed');
    }
    stdout("OK\n");

    stdout("Export public key...\n");
    $publicKey = $privateKey->getPublicKey();
    $publicKeyPem = $publicKey->getPublicKeyPem();
    if (!str_contains($publicKeyPem, 'BEGIN PUBLIC KEY')) {
        throw new TestFailedException('Exporting public key failed');
    }
    stdout("OK\n");

    stdout("Load private key...\n");
    $privateKey = new PrivateKeyRSA($privateKeyPem);
    stdout("OK\n");

    stdout("Load public key...\n");
    $publicKey = new PublicKeyRSA($publicKeyPem);
    stdout($publicKey->getThumbprint() . "\n");
    stdout("OK\n");

    /** @var SignatureAlgorithm[] $algs */
    $algs = [
        SignatureAlgorithm::SHA256,
        SignatureAlgorithm::SHA384,
        SignatureAlgorithm::SHA512,
    ];
    $data = str_repeat('Murka ', rand(1000, 2000));

    foreach ($algs as $alg) {
        $algName = $alg->toString();
        stdout("Create $algName signature...\n");
        $signer = $privateKey->getSigner($alg);
        $signature = $signer->sign($data);
        stdout("OK\n");

        stdout("Verify $algName signature...\n");
        $verifier = $publicKey->getVerifier($alg);

        $ok = $verifier->verify($data, $signature);
        if ($ok !== true) {
            throw new TestFailedException('Signature verification failed');
        }

        $signature = $signer->sign($data);
        $opensslPublicKey = OpenSSL::getPublicKey($publicKeyPem);
        $ok = OpenSSL::verify($data, $signature, $opensslPublicKey, $alg);
        if ($ok !== true) {
            throw new TestFailedException('Failed to verify signature with openssl');
        }

        stdout("OK\n");
    }
})();
