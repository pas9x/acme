<?php

namespace pas9x\letsencrypt;

class Certificate
{
    /** @var KeyPair $keys */
    public $keys;

    /** @var CSR $csr */
    public $csr;

    /** @var string[] $chain */
    public $chain;

    /** @var Order $order */
    public $order;
}