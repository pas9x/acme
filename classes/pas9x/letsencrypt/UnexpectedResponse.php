<?php

namespace pas9x\letsencrypt;

class UnexpectedResponse extends \Exception
{
    public $additional;

    public function __construct($message = null, $additional = null)
    {
        $this->additional = $additional;
        $finalMessage = 'Unexpected response from ACME server';
        if (!empty($message)) {
            $finalMessage .= ': ' . $message;
        }
        parent::__construct($finalMessage);
    }
}