<?php

namespace pas9x\letsencrypt;

use \Exception;
use \Throwable;

class CurlRequest
{
    public $curlOptions = [
        CURLOPT_RETURNTRANSFER => 1,
        CURLOPT_TIMEOUT => 15,
    ];
    public $requestHeaders = [];
    public $onDone = [];

    public $responseCode = null;
    public $responseHeaders = null;
    public $responseBody = null;
    public $curlErrorCode = null;
    public $curlErrorMessage = null;
    public $curlInfo = null;
    public $exception = null;
    public $success = null;

    protected $done = false;
    protected $headerCounter = 0;

    public function __construct($url)
    {
        $this->curlOptions[CURLOPT_URL] = $url;
    }

    public function post($postdata = null)
    {
        $this->curlOptions[CURLOPT_POST] = 1;
        if ($postdata !== null) {
            $this->curlOptions[CURLOPT_POSTFIELDS] = $postdata;
        }
    }

    public function ignoreInvalidSsl()
    {
        $this->curlOptions[CURLOPT_SSL_VERIFYHOST] = 0;
        $this->curlOptions[CURLOPT_SSL_VERIFYPEER] = 0;
    }

    public function execute()
    {
        if ($this->done) {
            throw new Exception('Reuse is prohibited');
        }
        $this->curlOptions[CURLOPT_HEADERFUNCTION] = function($ch, $header) {
            return $this->onHeader($ch, $header);
        };

        $headers = [];
        foreach ($this->requestHeaders as $headerName => $headerValues) {
            $normalizedHeaderName = ucwords($headerName, '-');
            $multipleHeaderValues = is_array($headerValues) ? $headerValues : array($headerValues);
            foreach ($multipleHeaderValues as $headerValue) {
                $headers[] = $normalizedHeaderName . ': ' . $headerValue;
            }
        }
        if (!empty($headers)) {
            $this->curlOptions[CURLOPT_HTTPHEADER] = $headers;
        }

        $ch = curl_init();
        curl_setopt_array($ch, $this->curlOptions);
        try {
            $this->responseBody = curl_exec($ch);
        } catch (Exception $e) {
            $this->exception = $e;
        } catch (Throwable $e) {
            $this->exception = $e;
        }

        $this->done = true;

        $this->curlErrorCode = curl_errno($ch);
        $this->curlErrorMessage = curl_error($ch);
        $this->curlInfo = curl_getinfo($ch);
        curl_close($ch);
        $this->success = is_string($this->responseBody) && empty($this->exception);

        if ($this->success) {
            $this->responseCode = $this->curlInfo['http_code'];
        } else {
            $message = 'cURL request failed';
            if (!empty($this->curlErrorCode) || !empty($this->curlErrorMessage)) {
                $message .= ': ' . $this->curlErrorMessage . ' (' . $this->curlErrorCode . ')';
            }
            throw new Exception($message);
        }

        if (is_array($this->onDone)) foreach ($this->onDone as $callback) {
            if (is_callable($callback)) {
                $callback($this);
            }
        }
    }

    protected function onHeader($ch, $header)
    {
        $this->headerCounter++;
        if ($this->headerCounter === 1) {
            goto end;
        }
        $pieces = explode(':', $header, 2);
        $headerName = mb_strtolower(trim($pieces[0]), 'UTF-8');
        $headerValue = isset($pieces[1]) ? trim($pieces[1]) : '';
        if (!empty($headerName)) {
            $this->responseHeaders[$headerName][] = $headerValue;
        }
        end:
        return strlen($header);
    }
}