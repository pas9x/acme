<?php

namespace pas9x\acme\implementations\http;

use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\StreamInterface;

class Message extends Cloneable implements MessageInterface
{
    protected $protocolVersion = '1.1';
    protected $headers = [];
    protected $body = '';

    public function __construct(string $protocolVersion, array $headers, string $body)
    {
        $this->protocolVersion = $protocolVersion;
        $this->body = $body;
        foreach ($headers as $name => $value) {
            $this->headers[strtolower($name)] = $value;
        }
    }

    public function getProtocolVersion()
    {
        return $this->protocolVersion;
    }

    public function withProtocolVersion($version)
    {
        return $this->withOne('protocolVersion', $version);
    }

    public function getHeaders()
    {
        return $this->headers;
    }

    public function hasHeader($name)
    {
        return isset($this->headers[strtolower($name)]);
    }

    public function getHeader($name)
    {
        $nameL = strtolower($name);
        return $this->hasHeader($nameL) ? $this->headers[$nameL] : [];
    }

    public function getHeaderLine($name)
    {
        return implode(',', $this->getHeader($name));
    }

    public function withHeader($name, $value)
    {
        $headers = $this->headers;
        $headers[strtolower($name)] = is_array($value) ? $value : [$value];
        return $this->withOne('headers', $headers);
    }

    public function withAddedHeader($name, $value)
    {
        $headers = $this->headers;
        $addValues = is_array($value) ? $value : [$value];
        $nameL = strtolower($name);
        foreach ($addValues as $addValue) {
            $headers[$nameL][] = $addValue;
        }
        return $this->withOne('headers', $headers);
    }

    public function withoutHeader($name)
    {
        $headers = $this->headers;
        unset($headers[strtolower($name)]);
        return $this->withOne('headers', $headers);
    }

    public function getBody()
    {
        return new StringStream($this->body);
    }

    public function withBody(StreamInterface $body)
    {
        return $this->withOne('body', $body->__toString());
    }
}