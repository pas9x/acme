<?php

use \pas9x\letsencrypt\LetsEncrypt;

require_once __DIR__ . '/includes/bootstrap.php';

$testCode = function(LetsEncrypt $le) {
    stdout("OK\n");
};

stdout("\n*** Register account test ***\n");
runTest($testCode);
