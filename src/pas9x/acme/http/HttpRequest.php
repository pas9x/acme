<?php

namespace pas9x\acme\http;

class HttpRequest
{
    /**
     * @var array<string,array<string,string>> $headers
     */
    public array $headers = [];

    /**
     * @param string $url
     * @param string $method
     * @param array<string,string>|array<string,array<string,string>> $headers
     * @param string|null $body
     */
    public function __construct(
        public string $url,
        public string $method = 'GET',
        array $headers = [],
        public ?string $body = null
    )
    {
        $this->headers = $this->normalizeHeaders($headers);
    }

    protected function normalizeHeaders(array $headers): array
    {
        $normalizedHeaders = [];
        foreach ($headers as $name => $values) {
            $normalizedHeaders[$name] = is_array($values) ? $values : [$values];
        }
        return $normalizedHeaders;
    }

    /**
     * @param string $name
     * @param scalar $value
     * @return void
     */
    public function header(string $name, $value, bool $replace = false): void
    {
        $name = trim(strtolower($name));
        if ($replace) {
            $this->headers[$name] = [strval($value)];
        } else {
            $this->headers[$name][] = strval($value);
        }
    }

    public function __toString(): string
    {
        $result = $this->method . ' ' . $this->url . "\n";
        foreach ($this->headers as $name => $values) {
            foreach ($values as $value) {
                $result .= $name . ': ' . $value . "\n";
            }
        }
        $result .= "\n";
        $result .= $this->body;
        return $result;
    }
}