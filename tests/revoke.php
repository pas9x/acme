<?php

use \pas9x\letsencrypt\LetsEncrypt;
use \pas9x\letsencrypt\LetsEncryptEntrails;

require_once __DIR__ . '/includes/bootstrap.php';

$testCode = function(LetsEncrypt $le) {
    $certFile = __DIR__ . '/certificate.pem';
    if (!file_exists($certFile)) {
        stderr("Cannot revoke certificate. File $certFile does not exist.\n");
        return;
    }
    $pems = file_get_contents($certFile);
    $chain = LetsEncryptEntrails::parseCertificateChain($pems);
    $certifificatePem = $chain[0];
    stdout("Revocation certificate...\n");
    $le->revokeCertificate($certifificatePem);
    $files = [
        /*
        __DIR__ . '/domain.key',
        __DIR__ . '/domain.csr',
        __DIR__ . '/domain.pem',
        __DIR__ . '/certificate.pem',
        */
    ];
    foreach ($files as $file) if (file_exists($file)) unlink($file);
    stdout("OK\n");
};

stdout("\n*** Certificate revocation test ***\n");
runTest($testCode);
