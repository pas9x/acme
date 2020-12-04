<?php

namespace pas9x\acme\implementations\http\curl;

use pas9x\acme\contracts\HttpResponse;
use pas9x\acme\implementations\http\curl\CurlClient;

class CurlResponse implements HttpResponse
{
    protected $client;
    protected $code;
    protected $message;
    protected $protocol;
    protected $headers;
    protected $body;

    public function __construct(CurlClient $client, int $code, string $message, string $protocol, array $headers, string $body)
    {
        $this->client = $client;
        $this->code = $code;
        $this->message = $message;
        $this->protocol = $protocol;
        $this->headers = $headers;
        $this->body = $body;
    }

    public function client(): CurlClient
    {
        return $this->client;
    }

    public function code(): int
    {
        return $this->code;
    }

    public function protocol(): string
    {
        return $this->protocol;
    }

    public function headers(): array
    {
        return $this->headers;
    }

    public function body(): string
    {
        return $this->body;
    }

    public function __toString(): string
    {
        $result = $this->protocol . ' ' . $this->code . ' ' . $this->message . "\r\n";
        foreach ($this->headers as $name => $values) {
            foreach ($values as $value) {
                $result .= "$name: $value\r\n";
            }
        }
        $result .= "\r\n";
        $result .= $this->body;
        return $result;
    }
}