<?php

use \pas9x\letsencrypt\LetsEncrypt;

require_once __DIR__ . '/includes/bootstrap.php';

$testCode = function(LetsEncrypt $le) {
    $onStatus = function($id, $message) {
        stdout("$id    $message\n");
    };
    $email = getConfig('email');

    $domainsConfig = getConfig('domains');

    $verifiers = [];
    foreach ($domainsConfig as $domain => $config) {
        if ($config['verifyMethod'] === 'http') {
            $verifiers[] = new HttpVerifier($domain, $config['documentRoot']);
        } elseif ($config['verifyMethod'] === 'dns') {
            $verifiers[] = new DnsVerifier($domain);
        } else {
            throw new Exception('Unknown verifyMethod for domain ' . $domain);
        }
    }

    $primaryVerifier = $verifiers[0];
    $additionalVerifiers = array_slice($verifiers, 1);

    $cert = $le->registerCertificate($email, $primaryVerifier, $additionalVerifiers, [], 60, $onStatus);
    file_put_contents(__DIR__ . '/domain.key', $cert->keys->privateKeyPem);
    file_put_contents(__DIR__ . '/domain.csr', $cert->csr->pem);
    file_put_contents(__DIR__ . '/certificate.pem', implode("\n\n", $cert->chain));
    stdout("OK\n");
};

stdout("\n*** Certificate registration test ***\n");
runTest($testCode);
