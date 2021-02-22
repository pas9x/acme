<?php

namespace pas9x\acme\implementations\http;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\UriInterface;

class CurlRequest extends Message implements RequestInterface
{
    protected $url;
    protected $method;
    
    /**
     * @param string $url
     * @param string $method
     * @param array $headers
     * @param string $protocolVersion
     * @param string $body
     */
    public function __construct(string $url, string $method, array $headers, string $body = '')
    {
        $this->url = $url;
        $this->method = $method;
        foreach ($headers as $name => $value) {
            $this->headers[$name] = is_array($value) ? $value : [$value];
        }
        parent::__construct('1.1', $headers, $body);
    }

    public function getRequestTarget()
    {
        return $this->url;
    }

    public function withRequestTarget($requestTarget)
    {
        return $this->withOne('url', $requestTarget);
    }

    public function getMethod()
    {
        return $this->method;
    }

    public function withMethod($method)
    {
        return $this->withOne('method', $method);
    }

    public function getUri()
    {
        return new URI($this->url);
    }

    public function withUri(UriInterface $uri, $preserveHost = false)
    {
        if ($preserveHost) {
            $oldUri = $this->getUri();
            $oldHost = $oldUri->getHost();
            $newHost = $uri->getHost();
            if ($newHost === '') {
                $uri = $uri->withHost($oldHost);
            }
        }
        return $this->withOne('url', $uri->__toString());
    }
}