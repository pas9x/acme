<?php

use pas9x\acme\enums\ECKeyCurve;
use pas9x\acme\crypto\PrivateKeyEC;
use pas9x\acme\crypto\CSR;
use pas9x\acme\crypto\DistinguishedName;

require_once __DIR__ . '/../bootstrap.php';

// TODO: make more detailed and strict test
(function () {
    $dn = DistinguishedName::create('pascalhp.net');
    $privateKey = PrivateKeyEC::generate(ECKeyCurve::P256);
    $csr = CSR::generate($dn, ['pascalhp.net', 'www.pascalhp.net'], ['127.0.0.1'], $privateKey);

    echo "DN: ";
    print_r($csr->distinguishedName);
    echo "SAN domains: ";
    print_r($csr->getSanDomains());
    echo "SAN ips: ";
    print_r($csr->getSanIps());
    echo "Private key:\n" . $privateKey->getPrivateKeyPem() . "\n";
})();
