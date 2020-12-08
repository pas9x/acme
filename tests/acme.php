<?php

require_once __DIR__ . '/includes/bootstrap.php';

$testName = $argv[1] ?? null;
$ca = $argv[2] ?? null;

$usage  = "Usage: php acme.php <test> <ca>\n";
$usage .= "Available tests:\n";
$usage .= "\tregister_account\n";
$usage .= "\tnew_order\n";
$usage .= "\tget_order\n";
$usage .= "\tvalidate_http_01\n";
$usage .= "\tvalidate_dns_01\n";
$usage .= "\tregister_certificate\n";
$usage .= "\tdownload_certificate\n";
$usage .= "\tkey_change\n";
$usage .= "\tupdate_contacts\n";
$usage .= "\tdeactivate\n";
$usage .= "Available CA: " . implode(', ', array_keys(getConfig('ca', []))) . "\n";

if ($testName === null) {
    stdout("No test specified.\n");
    stdout($usage);
    exit;
}

if ($ca === null) {
    stdout("No CA specified.\n");
    stdout($usage);
    exit;
}

requireConfig();

$tester = new AcmeTest($ca);
$red = CS_RED;
$green = CS_GREEN;
$reset = CS_RESET;

try {
    $challengeMethods = [
        'validate_http_01' => 'http-01',
        'validate_dns_01' => 'dns-01',
    ];

    if ($testName === 'register_account') {
        $account = $tester->getAccount(true);
        stdout("{$green}Account:{$reset} ");
        stdout(print_r($account->raw(), true));
    }

    elseif (in_array($testName, ['new_order', 'get_order'])) {
        $order = $tester->getOrder($testName === 'new_order');
        stdout("{$green}Order:{$reset} ");
        stdout(print_r($order->raw(), true) . "\n");
        foreach ($order->authorizations() as $authorizationIndex => $authorization) {
            stdout("{$green}Authorization #{$authorizationIndex}:{$reset} ");
            stdout(print_r($authorization->raw(), true) . "\n");
            foreach ($authorization->challenges() as $challengeIndex => $challenge) {
                stdout("{$green}Authorization #{$authorizationIndex} challenge {$challengeIndex}:{$reset} ");
                stdout(print_r($challenge->raw(), true) . "\n");
            }
        }
    }

    elseif (isset($challengeMethods[$testName])) {
        $type = $challengeMethods[$testName];
        $order = $tester->getOrder(false);
        foreach ($order->authorizations() as $authorizationIndex => $authorization) {
            if ($authorization->status() === 'valid') {
                stdout("Authorization #{$authorizationIndex} (" . $authorization->identifier()->value() . ") is valid. Skipping.\n");
                continue;
            }
            $selectedChallenge = null;
            $allChallengeTypes = [];
            foreach ($authorization->challenges() as $challengeIndex => $challenge) {
                $allChallengeTypes[] = $challenge->type();
                if ($challenge->type() === $type) {
                    $selectedChallenge = $challenge;
                }
            }
            if ($selectedChallenge === null) {
                fatal("Authorization #{$authorizationIndex} (" . $authorization->identifier()->value() . ") has no $type challenge. Available challenges: " . implode(', ', $allChallengeTypes) . "\n");
            }
            $verificationData = $selectedChallenge->verificationData();
            if ($type === 'http-01') {
                stdout("$type verification for domain " . $authorization->identifier()->value() . "\n");
                stdout("\tFile URI: ". $verificationData->fileUri() . "\n");
                stdout("\tFile content: ". $verificationData->fileContent() . "\n");
                readln('Place verification file and press [enter] ');
            } elseif ($type === 'dns-01') {
                stdout("$type verification for domain " . $authorization->identifier()->value() . "\n");
                stdout("\t_acme-challenge." . $authorization->identifier()->value() . " = " . $verificationData->txtRecord() . "\n");
                readln('Set TXT record and press [enter] ');
            } else {
                throw new LogicException;
            }
            $selectedChallenge->validate();
        }
        stdout("Wait 15 seconds and run get_order to check order status.\n");
    }

    elseif ($testName === 'register_certificate') {
        $order = $tester->getOrder(false);
        $order->registerCertificate();
        print_r($order->raw());
    }

    elseif ($testName === 'download_certificate') {
        $order = $tester->getOrder(false);
        $cert = $order->downloadCertificate();
    }

    elseif ($testName === 'revoke_certificate') {
        $tester->revokeCertificate();
    }

    elseif ($testName === 'key_change') {
        $tester->keyChange();
    }

    elseif ($testName === 'update_contacts') {
        $account = $tester->getAccount(false);
        $account->updateContacts(['mailto:spam@pascalhp.net']);
    }

    elseif ($testName === 'deactivate') {
        $tester->deactivate();
    }

    else {
        fatal("Unknown test: $testName\n");
    }

    stdout("OK\n");

} catch (Throwable $e) {
    $exceptionStr = $e->__toString();
    //$exceptionStr = preg_replace('/^.+\:/U', "{$red}\\0{$reset}", $e->__toString());

    stderr($exceptionStr . "\n\n");
    $request = $tester->acme->httpClient()->lastRequest();
    $response = $tester->acme->httpClient()->lastResponse();
    if (!empty($request)) {
        stderr("{$red}Last request:{$reset}\n");
        stderr($request->__toString() . "\n\n");
    }
    if (!empty($response)) {
        stderr("{$red}Last response:{$reset}\n");
        stderr($response->__toString() . "\n\n");
    }
    exit(1);
}