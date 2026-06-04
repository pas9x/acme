<?php

use pas9x\acme\enums\ECKeyCurve;
use pas9x\acme\crypto\PrivateKeyEC;
use pas9x\acme\crypto\PublicKeyEC;
use pas9x\acme\enums\SignatureAlgorithm;
use test\TestFailedException;
use test\OpenSSL;

require_once __DIR__ . '/../bootstrap.php';

(function () {
    /** @var ECKeyCurve[] $curves */
    $curves = [
        ECKeyCurve::P256,
        ECKeyCurve::P384,
        ECKeyCurve::P521,
        ECKeyCurve::ED448,
        ECKeyCurve::ED25519,
    ];

    /** @var SignatureAlgorithm[] $algs */
    $algs = [
        SignatureAlgorithm::SHA256,
        SignatureAlgorithm::SHA384,
        SignatureAlgorithm::SHA512,
    ];

    foreach ($curves as $curve) {
        $curveName = $curve->toPhpseclibCode();
        stdout("Generate $curveName private key...\n");
        $privateKey = PrivateKeyEC::generate($curve);
        $privateKeyPem = $privateKey->getPrivateKeyPem();
        if (!str_contains($privateKeyPem, 'BEGIN PRIVATE KEY')) {
            throw new TestFailedException('Exporting private key failed');
        }
        stdout("OK\n");

        stdout("Export $curveName public key...\n");
        $publicKey = $privateKey->getPublicKey();
        $publicKeyPem = $publicKey->getPublicKeyPem();
        if (!str_contains($publicKeyPem, 'BEGIN PUBLIC KEY')) {
            throw new TestFailedException('Exporting public key failed');
        }
        stdout("OK\n");

        stdout("Load $curveName private key...\n");
        $privateKey = new PrivateKeyEC($privateKeyPem);
        stdout("OK\n");

        stdout("Load $curveName public key...\n");
        $publicKey = new PublicKeyEC($publicKeyPem);
        stdout($publicKey->getThumbprint() . "\n");
        stdout("OK\n");

        $opensslPublicKey = OpenSSL::getPublicKey($publicKeyPem);

        $data = str_repeat('Murka ', rand(1000, 2000));

        // ---------- ED448, ED25519 curve
        if (in_array($curve, [ECKeyCurve::ED448, ECKeyCurve::ED25519])) {
            stdout("Create $curveName signature...\n");
            $signer = $privateKey->getDefaultSigner();
            $signature = $signer->sign($data);
            stdout("OK\n");

            stdout("Verify $curveName signature...\n");
            $verifier = $publicKey->getDefaultVerifier();

            $ok = $verifier->verify($data, $signature);
            if ($ok !== true) {
                throw new TestFailedException('Signature verification failed');
            }

            if (version_compare(PHP_VERSION, '8.4.0') >= 0) {
                $signer->asn1SignatureFormat = true;
                $opensslSignature = $signer->sign($data);
                $ok = OpenSSL::verify($data, $opensslSignature, $opensslPublicKey, null);
                if ($ok !== true) {
                    throw new TestFailedException('Failed to verify signature with openssl');
                }
            }

            stdout("OK\n");
            continue;
        }

        // ---------- P-256, P-384, P-521 curve
        foreach ($algs as $alg) {
            $algName = $alg->toString();
            stdout("Create $curveName $algName signature...\n");
            $signer = $privateKey->getSigner($alg);
            $signature = $signer->sign($data);
            stdout("OK\n");

            stdout("Verify $curveName $algName signature...\n");
            $verifier = $publicKey->getVerifier($alg);

            $ok = $verifier->verify($data, $signature);
            if ($ok !== true) {
                throw new TestFailedException('Signature verification failed');
            }

            $signer->asn1SignatureFormat = true;
            $opensslSignature = $signer->sign($data);
            $ok = OpenSSL::verify($data, $opensslSignature, $opensslPublicKey, $alg);
            if ($ok !== true) {
                throw new TestFailedException('Failed to verify signature with openssl');
            }

            stdout("OK\n");
        }
    }
})();
