<?php

use test\AcmeTest;
use test\KeyParams;
use pas9x\acme\enums\KeyType;
use pas9x\acme\enums\ECKeyCurve;

require_once __DIR__ . '/bootstrap.php';

$accpuntKeyParams = new KeyParams(KeyType::EC, ECKeyCurve::P256, null);
$domainKeyParams = new KeyParams(KeyType::EC, ECKeyCurve::P384, null);

$tester = new AcmeTest(config()->ca['letsencrypt'], $accpuntKeyParams, $domainKeyParams);

$account = $tester->getAccount();
$order = $tester->getOrder();
$tester->confirmWithWebroot();
$cert = $tester->registerCertificate();

echo "Certificate successfully registered.\n";
