<?php

use pas9x\acme\crypto\Certificate;
use pas9x\acme\crypto\PublicKeyEC;
use pas9x\acme\crypto\PublicKeyRSA;
use test\TestFailedException;

require_once __DIR__ . '/../bootstrap.php';

(function () {
    $files = [
        'pascalhp-net.pem',
        'stallman-org.pem',
        'stallman-org-chain.pem',
        'dns.google.pem',
    ];

    foreach ($files as $file) {
        echo "******************** $file ********************\n";
        $pem = file_get_contents(__DIR__ . '/' . $file);
        $cert = new Certificate($pem);

        $cert2 = new Certificate($cert->pem);
        if (!str_contains($cert2->pem, 'BEGIN CERTIFICATE')) {
            throw new TestFailedException('Export certificate pem failed');
        }

        $publicKey = $cert->getPublicKey();
        $keyType = $publicKey->keyType->toString();
        if ($publicKey->delegate instanceof PublicKeyEC) {
            $keyType .= ' ' . $publicKey->delegate->curve->toNistCode();
        } elseif ($publicKey->delegate instanceof PublicKeyRSA) {
            $keyType .= ' ' . $publicKey->delegate->bits;
        }

        echo 'Suggested name: ' . $cert->suggestedCertificateName . "\n";
        echo 'SAN names ';
        print_r($cert->sanNames);
        echo 'Issuance date: ' . gmdate('Y-m-d H:i:s', $cert->notAfter) . " UTC\n";
        echo 'Expiration date: ' . gmdate('Y-m-d H:i:s', $cert->notAfter) . " UTC\n";
        echo 'Subject key identifier: ' . $cert->subjectKeyIdentifier . "\n";
        echo 'Authority key identifier: ' . $cert->authorityKeyIdentifier . "\n";
        echo 'Is CA: ' . ($cert->isCA ? 'yes' : 'no') . "\n";
        echo "Public key ($keyType):\n";
        echo trim($publicKey->getPublicKeyPem()) . "\n";
        echo "\n";
    }
})();
