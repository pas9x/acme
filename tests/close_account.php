<?php

use \pas9x\letsencrypt\LetsEncrypt;

require_once __DIR__ . '/includes/bootstrap.php';

$testCode = function(LetsEncrypt $le) {
    stdout("Getting account...\n");
    $account = $le->getAccount();
    stdout("Deactivating account...\n");
    $account->deactivate();
    $accountFile = __DIR__ . '/account.json';
    if (file_exists($accountFile)) {
        unlink($accountFile);
    }
    stdout("OK\n");
};

stdout("\n*** Close account test ***\n");
runTest($testCode);
