<?php

namespace pas9x\acme\implementations\http\curl;

use pas9x\acme\contracts\HttpRequest;

class CurlRequest implements HttpRequest
{
    protected $client;
    protected $method;
    protected $url;
    protected $headers;
    protected $postdata;

    public function __construct(CurlClient $client, string $method, string $url, array $headers, $postdata)
    {
        $this->client = $client;
        $this->method = $method;
        $this->url = $url;
        $this->headers = $headers;
        $this->postdata = $postdata;
    }

    public function client(): CurlClient
    {
        return $this->client;
    }

    public function method(): string
    {
        return $this->method;
    }

    public function url(): string
    {
        return $this->url;
    }

    public function headers(): array
    {
        return $this->headers;
    }

    public function postdata()
    {
        return $this->postdata;
    }

    public function __toString(): string
    {
        $pieces = parse_url($this->url);
        $uri = '';
        if (isset($pieces['path'])) {
            $uri .= $pieces['path'];
        }
        if (isset($pieces['query'])) {
            $uri .= '?' . $pieces['query'];
        }

        $result = $this->method . " $uri\r\n";
        foreach ($this->headers as $name => $value) {
            $result .= "$name: $value\r\n";
        }
        $result .= "\r\n" . trim(print_r($this->postdata, true));
        return $result;
    }
}