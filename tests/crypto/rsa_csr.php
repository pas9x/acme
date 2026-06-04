<?php

use pas9x\acme\crypto\PrivateKeyRSA;
use pas9x\acme\crypto\CSR;
use pas9x\acme\crypto\DistinguishedName;

require_once __DIR__ . '/../bootstrap.php';

// TODO: make more detailed and strict test
(function () {
    $dn = DistinguishedName::create('pascalhp.net');
    $privateKey = PrivateKeyRSA::generate(2048);
    $csr = CSR::generate($dn, ['pascalhp.net', 'www.pascalhp.net'], ['127.0.0.1'], $privateKey);

    echo "DN: ";
    print_r($csr->distinguishedName);
    echo "SAN domains: ";
    print_r($csr->getSanDomains());
    echo "SAN ips: ";
    print_r($csr->getSanIps());
    echo "Private key:\n" . $privateKey->getPrivateKeyPem() . "\n";
})();