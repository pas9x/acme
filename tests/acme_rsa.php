<?php

use test\AcmeTest;
use test\KeyParams;
use pas9x\acme\enums\KeyType;

require_once __DIR__ . '/bootstrap.php';

$accpuntKeyParams = new KeyParams(KeyType::RSA, null, 2048);
$domainKeyParams = new KeyParams(KeyType::RSA, null, 4096);

$tester = new AcmeTest(config()->ca['letsencrypt'], $accpuntKeyParams, $domainKeyParams);

$account = $tester->getAccount();
$order = $tester->getOrder();
$tester->confirmWithWebroot();
$cert = $tester->registerCertificate();

echo "Exit.\n";
