<?php

use phpseclib\Crypt\RSA;
use pas9x\acme\implementations\crypto\RSACSR;
use pas9x\acme\dto\DistinguishedName;
use pas9x\acme\Utils;

require_once __DIR__ . '/../includes/bootstrap.php';

define('CRYPT_RSA_MODE', RSA::MODE_INTERNAL);

(function () {
    stdout("Generate RSA CSR (phpseclib)...\n");
    $dn = new DistinguishedName('75m.net');
    $dn->organizationName('orgname');
    $dn->organizationalUnit('orgunit');
    $dn->locality('locality');
    $dn->state('state');
    $dn->country('KP');
    $dn->emailAddress('admin@75m.net');
    $csr = RSACSR::generate($dn, ['www.75m.net', 'test.75m.net'], ['8.8.8.8', '1.1.1.1'], null, null, Utils::ENGINE_PHPSECLIB);
    $privateKeyPem = $csr->getPrivateKey()->getPrivateKeyPem();
    if (!preg_match('/BEGIN RSA PRIVATE KEY/', $privateKeyPem)) {
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
