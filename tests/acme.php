<?php

use test\AcmeTest;

require_once __DIR__ . '/bootstrap.php';

$tester = new AcmeTest(config()->ca['letsencrypt']);

$tester->getAccount();
echo "OK\n";
