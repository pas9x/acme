<?php

namespace pas9x\acme\http;

class HttpResponse
{
    public readonly ?string $contentType;

    /**
     * @param int $code
     * @param array<string,array<string,string>> $headers $headers
     * @param string $body
     */
    public function __construct(
        public readonly int $code,
        public readonly array $headers,
        public readonly string $body
    )
    {
        $this->contentType = $this->header('Content-Type');
    }

    public function header(string $name, ?string $defaultValue = null): ?string
    {
        $nameLC = strtolower($name);
        if (!isset($this->headers[$nameLC])) {
            return $defaultValue;
        }
        $values = $this->headers[$nameLC];
        $count = count($values);
        if ($count < 1) {
            return $defaultValue;
        }
        if ($count === 1) {
            return $values[0];
        }
        throw new \RuntimeException("There is $count values of header `$name`. Don't know which one to return.");
    }

    public function __toString(): string
    {
        $result = "HTTP code = " . $this->code . "\n";
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