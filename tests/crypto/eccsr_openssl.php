<?php

use pas9x\acme\implementations\crypto\ECCSR;
use pas9x\acme\dto\DistinguishedName;

require_once __DIR__ . '/../includes/bootstrap.php';

(function () {
    stdout("Generate EC CSR...\n");
    $dn = new DistinguishedName('75m.net');
    $dn->organizationName('orgname');
    $dn->organizationalUnit('orgunit');
    $dn->locality('locality');
    $dn->state('state');
    $dn->country('KP');
    $dn->emailAddress('admin@75m.net');
    $csr = ECCSR::generate($dn, ['www.75m.net', 'test.75m.net'], ['8.8.8.8', '1.1.1.1']);
    $privateKeyPem = $csr->getPrivateKey()->getPrivateKeyPem();
    if (!preg_match('/BEGIN EC PRIVATE KEY/', $privateKeyPem)) {
        fatal("Failed to generate private key: $privateKeyPem\n");
    }
    $csrPem = $csr->getCsrPem();
    if (!preg_match('/BEGIN CERTIFICATE REQUEST/', $csrPem)) {
        fatal("Failed to generate CSR: $csrPem\n");
    }
    //stdout($privateKeyPem);
    //stdout($csrPem);
    stdout("OK\n");
})();
