<?php

use pas9x\acme\crypto\SignerHMAC;
use pas9x\acme\enums\SignatureAlgorithm;
use test\TestFailedException;

require_once __DIR__ . '/../bootstrap.php';

(function () {
    /** @var SignatureAlgorithm[] $algs */
    $algs = [
        SignatureAlgorithm::SHA256,
        SignatureAlgorithm::SHA384,
        SignatureAlgorithm::SHA512,
    ];

    foreach ($algs as $alg) {
        $algName = $alg->toString();
        $data = str_repeat('Murka ', rand(1000, 2000));
        $key = random_bytes(rand(10, 2000));

        stdout("Check HMAC $algName...\n");
        $signer = new SignerHMAC($alg, $key);
        $signature = $signer->sign($data);
        $actualLength = strlen($signature);
        $expectedLength = intval(str_replace('sha', '', $algName)) / 8;
        if ($actualLength !== $expectedLength) {
            throw new TestFailedException("Expected signature length: $expectedLength");
        }
        echo "OK\n";
    }
})();
