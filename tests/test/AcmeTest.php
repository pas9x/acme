<?php

namespace test;

use test\config\CAConfig;

class AcmeTest
{
    use AcmeTest_logger;
    use AcmeTest_acme;
    use AcmeTest_account;
    use AcmeTest_order;
    use AcmeTest_cert;

    public function __construct(
        public readonly CAConfig $ca,
        public readonly KeyParams $accountKeyParams,
        public readonly KeyParams $certificateKeyParams,
    )
    {
    }
}
