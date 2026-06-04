<?php

namespace pas9x\acme\http;

class CurlWorker implements Worker
{
    /** @var array<int,mixed> */
    public $curlopt = [
        CURLOPT_TIMEOUT => 10,
    ];

    public function request(HttpRequest $request): HttpResponse
    {
        $ch = curl_init($request->url);

        $curlopt = $this->curlopt;
        $curlopt[CURLOPT_RETURNTRANSFER] = true;

        foreach ($request->headers as $name => $values) {
            $headers = [];
            foreach ($values as $value) {
                $headers[] = "$name: $value";
            }
            $curlopt[CURLOPT_HTTPHEADER] = $headers;
        }

        if ($request->method === 'POST') {
            $curlopt[CURLOPT_POST] = true;
        } elseif ($request->method === 'HEAD') {
            $curlopt[CURLOPT_NOBODY] = true;
        } elseif ($request->method !== 'GET') {
            $curlopt[CURLOPT_CUSTOMREQUEST] = $request->method;
        }

        if ($request->body !== null && $request->body !== '') {
            $curlopt[CURLOPT_POSTFIELDS] = $request->body;
        }

        $responseHeaders = [];
        $curlopt[CURLOPT_HEADERFUNCTION] = function ($ch, $header) use (&$responseHeaders) {
            $parts = explode(':', $header, 2);
            if (count($parts) === 2) {
                $name = strtolower(trim($parts[0]));
                $value = trim($parts[1]);
                $responseHeaders[$name][] = $value;
            }
            return strlen($header);
        };

        curl_setopt_array($ch, $curlopt);

        $responseBody = @curl_exec($ch);
        curl_close($ch);
        $errorCode = curl_errno($ch);

        if (!is_string($responseBody) || $errorCode !== CURLE_OK) {
            throw new \RuntimeException('cURL request failed: ' . curl_error($ch) . " (error code = $errorCode)");
        }

        return new CurlResponse(
            intval(curl_getinfo($ch, CURLINFO_HTTP_CODE)),
            $responseHeaders,
            $responseBody,
            curl_getinfo($ch)
        );
    }
}