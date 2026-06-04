<?php

namespace pas9x\acme\http;

class CurlResponse extends HttpResponse
{
    /**
     * @param int $code
     * @param array<string,array<string,string>> $headers $headers
     * @param string $body
     * @param array<string,mixed> $curlInfo
     */
    public function __construct(
        int $code,
        array $headers,
        string $body,
        public readonly array $curlInfo
    )
    {
        parent::__construct($code, $headers, $body);
    }
}