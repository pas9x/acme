<?php

namespace pas9x\acme\implementations\http;

use Psr\Http\Message\ResponseInterface;

class CurlResponse extends Message implements ResponseInterface
{
    protected $statusCode;
    protected $reasonPhrase = '';

    public function __construct(string $protocolVersion, array $headers, string $body, int $statusCode)
    {
        parent::__construct($protocolVersion, $headers, $body);
        $this->statusCode = $statusCode;
    }

    public function getStatusCode()
    {
        return $this->statusCode;
    }

    public function withStatus($code, $reasonPhrase = '')
    {
        $properties = [
            'statusCode' => $code,
            'reasonPhrase' => $reasonPhrase,
        ];
        return $this->withMany($properties);
    }

    public function getReasonPhrase()
    {
        return $this->reasonPhrase;
    }
}