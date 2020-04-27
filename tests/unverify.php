<?php

use \pas9x\letsencrypt\LetsEncrypt;

require_once __DIR__ . '/includes/bootstrap.php';

$testCode = function(LetsEncrypt $le) {
    $domains = array_keys(getConfig('domains'));
    stdout("Obtaining new order...\n");
    $order = $le->newOrder($domains);
    stdout("Order url: {$order->url}\n");
    stdout("Deactivating verification...\n");
    $order->deactivateVerification();
    stdout("OK\n");
};

stdout("\n*** Deactivate verification test ***\n");
runTest($testCode);
