<?php

namespace pas9x\letsencrypt;

class CSR
{
    /** @var KeyPair $keys */
    public $keys;

    /** @var string $pem */
    public $pem;

    /** @var string */
    public $der;
}