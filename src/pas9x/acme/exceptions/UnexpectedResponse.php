<?php

namespace pas9x\acme\exceptions;

class UnexpectedResponse extends \RuntimeException
{
    public readonly mixed $additional;

    public function __construct(?string $message = null, mixed $additional = null)
    {
        $this->additional = $additional;
        $finalMessage = 'Unexpected response from ACME server';
        if (!empty($message)) {
            $finalMessage .= ': ' . $message;
        }
        parent::__construct($finalMessage);
    }
}