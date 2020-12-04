<?php

namespace pas9x\acme\dto;

class Event
{
    protected $code;
    protected $details;

    const E_HTTP_REQUEST = 'http-request';
    const E_HTTP_RESPONSE = 'http-response';

    public function __construct(string $code, $details = null)
    {
        $this->code = $code;
        $this->details = $details;
    }

    public function code(): string
    {
        return $this->code;
    }

    public function details()
    {
        return $this->details;
    }
}