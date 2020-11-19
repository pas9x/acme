<?php

use \pas9x\letsencrypt\LetsEncrypt;
use \pas9x\letsencrypt\LetsEncryptInternals;
use \pas9x\letsencrypt\KeyPair;

function runTest(callable $testCode)
{
    $accountFile = dirname(__DIR__) . '/account.json';
    if (file_exists($accountFile)) {
        stdout("Using account keys from $accountFile\n");
        $accountInfo = LetsEncryptInternals::jsonDecode(file_get_contents($accountFile));
        $accountKeys = new KeyPair($accountInfo['privateKey']);
        $le = new LetsEncrypt($accountKeys, $accountInfo['accountUrl']);
        $registerAccount = false;
    } else {
        $accountKeys = KeyPair::generate(2048);
        $le = new LetsEncrypt($accountKeys, null);
        $registerAccount = true;
    }

    $le->directoryURL = getConfig('directoryUrl');
    $directoryFile = __DIR__ . '/../directory.json';
    if (file_exists($directoryFile)) {
        $le->directory = LetsEncryptInternals::jsonDecode(file_get_contents($directoryFile));
    } else {
        $directory = $le->getDirectory();
        file_put_contents($directoryFile, json_encode($directory, JSON_PRETTY_PRINT));
    }

    try {
        if ($registerAccount) {
            $email = getConfig('email');
            stdout("Registering account for {$email}...\n");
            $le->registerAccount($email, true);
            $accountInfo = [
                'privateKey' => $accountKeys->privateKeyPem,
                'accountUrl' => $le->accountUrl,
            ];
            file_put_contents($accountFile, json_encode($accountInfo, JSON_PRETTY_PRINT));
            stdout("Account registration successful\n");
        }
        $testCode($le);
    } catch (Throwable $e) {
        goto error;
    } catch (Exception $e) {
        error:
        stderr($e->__toString() . "\n");
        if (!empty($le->lastRequest)) {
            stderr("Response code: " . $le->lastRequest->responseCode . "\n");
            stderr("Response headers:\n");
            foreach ($le->lastRequest->responseHeaders as $headerName => $headerValues) {
                foreach ($headerValues as $headerValue) {
                    stderr("    $headerName: $headerValue\n");
                }
            }
            fatal("Response body: " . $le->lastRequest->responseBody . "\n");
        }
    }
}
