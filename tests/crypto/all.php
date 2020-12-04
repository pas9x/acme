<?php

require_once __DIR__ . '/../includes/bootstrap.php';

runScript(__DIR__ . '/ec_openssl.php');
runScript(__DIR__ . '/ec_eclib.php');
runScript(__DIR__ . '/rsa_openssl.php');
runScript(__DIR__ . '/rsa_phpseclib.php');
runScript(__DIR__ . '/hmac_hash.php');
runScript(__DIR__ . '/hmac_phpseclib.php');
