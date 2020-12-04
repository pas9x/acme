<?php

namespace pas9x\acme\implementations\http\curl;

use Throwable;
use InvalidArgumentException;
use pas9x\acme\contracts\HttpClient;
use pas9x\acme\contracts\HttpRequest;
use pas9x\acme\contracts\HttpResponse;
use pas9x\acme\contracts\HttpWatcher;
use pas9x\acme\exceptions\HttpException;

class CurlClient implements HttpClient
{
    public $curlOptions = [];
    public $curl = null;
    public $curlInfo = null;
    public $curlErrno = null;
    public $curlErrstr = null;

    protected $lastRequest = null;
    protected $lastResponse = null;

    protected $responseProtocol = '';
    protected $responseMessage = '';
    protected $responseHeaders = [];
    protected $headerFunction;

    /** @var HttpWatcher[] */
    protected $watchers = [];

    public function __construct(array $curlOptions = [])
    {
        $this->curlOptions = $curlOptions;
        $this->headerFunction = function($ch, $header): int {
            return $this->onHeader($ch, $header);
        };
    }

    public function get(string $url, array $headers = []):  HttpResponse
    {
        $request = new CurlRequest($this, 'GET', $url, $headers, null);
        return $this->objRequest($request);
    }

    public function post(string $url, $postdata = null, array $headers = []):  HttpResponse
    {
        $request = new CurlRequest($this, 'POST', $url, $headers, $postdata);
        return $this->objRequest($request);
    }

    public function request(string $url, string $method, array $headers = [], $body = null): HttpResponse
    {
        $request = new CurlRequest($this, $method, $url, $headers, $body);
        return $this->objRequest($request);
    }

    public function objRequest(HttpRequest $request): HttpResponse
    {
        $this->curl = null;
        $this->curlInfo = null;
        $this->lastRequest = $request;
        $this->lastResponse = null;
        $this->responseProtocol = '';
        $this->responseMessage = '';
        $this->responseHeaders = [];

        foreach ($this->watchers as $watcher) {
            $watcher->onRequest($request, $this);
        }

        $ch = curl_init($request->url());
        if ($request->method() === 'POST') {
            curl_setopt($ch, CURLOPT_POST, 1);
        } elseif ($request->method() !== 'GET') {
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $request->method());
        }

        $postdata = $request->postdata();
        if (is_string($postdata) || is_array($postdata)) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $postdata);
        } elseif ($postdata !== null) {
            throw new InvalidArgumentException('Invalid type of $postdata: ' . gettype($postdata));
        }

        $headers = $request->headers();
        if (!empty($headers)) {
            if (isset($this->curlOptions[CURLOPT_HTTPHEADER])) {
                throw new InvalidArgumentException('You cannot use CURLOPT_HTTPHEADER option with $headers');
            }
            $curlHeaders = [];
            foreach ($headers as $name => $value) {
                $curlHeaders[] = "$name: $value";
            }
            curl_setopt($ch, CURLOPT_HTTPHEADER, $curlHeaders);
        }

        if (isset($this->curlOptions[CURLOPT_RETURNTRANSFER])) {
            throw new InvalidArgumentException('You cannot use CURLOPT_RETURNTRANSFER option');
        }
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

        if (isset($this->curlOptions[CURLOPT_HEADERFUNCTION])) {
            throw new InvalidArgumentException('You cannot use CURLOPT_HEADERFUNCTION option');
        }
        curl_setopt($ch, CURLOPT_HEADERFUNCTION, $this->headerFunction);

        if (!empty($this->curlOptions)) {
            curl_setopt_array($ch, $this->curlOptions);
        }

        $this->curl = $ch;

        try {
            $responseBody = curl_exec($ch);
        } catch (Throwable $e) {
        }

        $this->curlInfo = curl_getinfo($ch);
        $this->curlErrno = curl_errno($ch);
        $this->curlErrstr = curl_error($ch);
        curl_close($ch);

        if ($this->curlErrno !== CURLE_OK) {
            throw new HttpException('cURL request failed: ' . $this->curlErrstr . ' (' . $this->curlErrno . ')');
        }

        if (isset($e)) {
            throw new HttpException('cURL request exception: ' . $e->getMessage(), 0, $e);
        }

        if (!isset($responseBody) || !is_string($responseBody)) {
            throw new HttpException('cURL request failed (unknown reason)');
        }

        $this->lastResponse = new CurlResponse($this, $this->curlInfo['http_code'], $this->responseMessage, $this->responseProtocol, $this->responseHeaders, $responseBody);

        foreach ($this->watchers as $watcher) {
            $watcher->onResponse($this->lastResponse, $this);
        }

        return $this->lastResponse;
    }

    public function lastRequest(): ?HttpRequest
    {
        return $this->lastRequest;
    }

    public function lastResponse(): ?HttpResponse
    {
        return $this->lastResponse;
    }

    public function addWatcher(HttpWatcher $watcher)
    {
        $id = spl_object_hash($watcher);
        if (!isset($this->watchers[$id])) {
            $this->watchers[$id] = $watcher;
        }
    }

    protected function onHeader($ch, $header): int
    {
        if (preg_match('/^(HTTP\\/[0-9]+(\.[0-9]+)?)\s+[0-9]+(\s+.+)?$/i', trim($header), $matches)) {
            $this->responseProtocol = $matches[1];
            $this->responseMessage = isset($matches[3]) ? trim($matches[3]) : '';
            $this->responseHeaders = [];
        } else {
            $pieces = explode(':', $header, 2);
            $name = trim(strtolower($pieces[0]));
            $value = isset($pieces[1]) ? trim($pieces[1]) : '';
            if ($name !== '') {
                $this->responseHeaders[$name][] = $value;
            }
        }
        return strlen($header);
    }
}