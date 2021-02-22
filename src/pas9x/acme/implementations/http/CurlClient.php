<?php

namespace pas9x\acme\implementations\http;

use InvalidArgumentException;
use RuntimeException;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class CurlClient implements ClientInterface
{
    protected $lastRequest = null;
    protected $lastResponse = null;
    protected $lastErrorCode = null;
    protected $lastErrorMessage = null;
    protected $lastInfo = null;
    protected $curlOptions = [];
    protected static $restrictOptions = [
        CURLOPT_RETURNTRANSFER => 'CURLOPT_RETURNTRANSFER',
        CURLOPT_POST => 'CURLOPT_POST',
        CURLOPT_POSTFIELDS => 'CURLOPT_POSTFIELDS',
        CURLOPT_NOBODY => 'CURLOPT_NOBODY',
        CURLOPT_CUSTOMREQUEST => 'CURLOPT_CUSTOMREQUEST',
        CURLOPT_HEADER => 'CURLOPT_HEADER',
        CURLOPT_HTTPHEADER => 'CURLOPT_HTTPHEADER',
        CURLOPT_HEADERFUNCTION => 'CURLOPT_HEADERFUNCTION',
    ];
    
    protected $headerFunction;
    protected $responseProtocol = '';
    protected $responseMessage = '';
    protected $responseHeaders = [];
    
    public function __construct()
    {
        $this->headerFunction = function($ch, string $header) {
            $result = strlen($header);
            $header = trim($header);
            if (preg_match('/^([A-Z]{2,20}\\/[0-9]+(\.[0-9]+)?)\s+[0-9]+(\s+.+)?$/', $header, $matches)) {
                $this->responseHeaders = [];
                $this->responseProtocol = $matches[1];
                $this->responseMessage = $matches[3] ?? '';
            } else {
                $pieces = explode(':', $header, 2);
                $name = trim($pieces[0]);
                $value = isset($pieces[1]) ? trim($pieces[1]) : '';
                if ($name !== '') {
                    $this->responseHeaders[$name][] = $value;
                }
            }
            return $result;
        };
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $ch = curl_init($request->getUri()->__toString());
        $curlOptions = $this->curlOptions;
        $curlOptions[CURLOPT_RETURNTRANSFER] = 1;
        $curlOptions[CURLOPT_HEADERFUNCTION] = $this->headerFunction;
        
        $method = strtoupper($request->getMethod());
        if ($method !== 'GET') {
            if ($method === 'POST') {
                $curlOptions[CURLOPT_POST] = 1;
            } elseif ($method === 'HEAD') {
                $curlOptions[CURLOPT_NOBODY] = 1;
            } else {
                $curlOptions[CURLOPT_CUSTOMREQUEST] = $method;
            }
        }
        
        $body = $request->getBody()->getContents();
        if ($body !== '') {
            $curlOptions[CURLOPT_POSTFIELDS] = $body;
        }
        
        $headers = $request->getHeaders();
        if (is_array($headers)) {
            $curlHeaders = [];
            foreach ($headers as $name => $values) {
                $name = trim($name);
                if ($name === '') continue;
                foreach ((array)$values as $value) {
                    $curlHeaders[] = "$name: $value";
                }
            }
            if (!empty($curlHeaders)) {
                $curlOptions[CURLOPT_HTTPHEADER] = $curlHeaders;
            }
        }
        
        curl_setopt_array($ch, $curlOptions);
        $this->lastResponse = null;
        $this->lastRequest = $request;
        $this->responseHeaders = [];
        $responseBody = curl_exec($ch);
        $this->lastErrorCode = curl_errno($ch);
        $this->lastErrorMessage = curl_error($ch);
        $this->lastInfo = curl_getinfo($ch);
        curl_close($ch);
        if ($this->lastErrorCode !== CURLE_OK || !is_string($responseBody)) {
            throw new RuntimeException('cURL request failed: ' . $this->lastErrorMessage . ' (' . $this->lastErrorCode . ')');
        }

        $this->lastResponse = new CurlResponse($this->responseProtocol, $this->responseHeaders, $responseBody, $this->lastInfo['http_code']);
        return $this->lastResponse;
    }
    
    public function curlOptions(array $newOptions = null): array
    {
        if ($newOptions !== null) {
            foreach (array_keys($newOptions) as $option) {
                if (isset(static::$restrictOptions[$option])) {
                    throw new InvalidArgumentException(static::$restrictOptions[$option] . ' option is not allowed');
                }
            }
            $this->curlOptions = $newOptions;
        }
        return $this->curlOptions;
    }
}