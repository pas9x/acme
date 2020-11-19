<?php

use \pas9x\letsencrypt\LetsEncrypt;
use \pas9x\letsencrypt\LetsEncryptInternals;
use \pas9x\letsencrypt\KeyPair;

require_once __DIR__ . '/includes/bootstrap.php';

$testCode = function(LetsEncrypt $le) {
    $accountFile = __DIR__ . '/account.json';
    $accountInfo = LetsEncryptInternals::jsonDecode(file_get_contents($accountFile));
    $newKeys = KeyPair::generate(2048);
    stdout("Getting account...\n");
    $account = $le->getAccount();
    stdout("Requesting key change...\n");
    $account->keyChange($newKeys);
    $accountInfo['privateKey'] = $newKeys->privateKeyPem;
    file_put_contents($accountFile, json_encode($accountInfo, JSON_PRETTY_PRINT));
    stdout("OK\n");
};

stdout("\n*** Key change test ***\n");
runTest($testCode);
