<?php

namespace pas9x\acme\http;

use Psr\Http\Client\ClientInterface;
use Nyholm\Psr7\Request;

class PsrWorker implements Worker
{
    public function __construct(public ClientInterface $client)
    {
    }

    public function request(HttpRequest $request): HttpResponse
    {
        $req = new Request($request->method, $request->url, $request->headers, $request->body);
        $resp = $this->client->sendRequest($req);
        $response = new HttpResponse(
            $resp->getStatusCode(),
            $this->processHeaders($resp->getHeaders()),
            $resp->getBody()->getContents()
        );
        return $response;
    }

    protected function processHeaders(array $headers): array
    {
        $result = [];
        foreach ($headers as $name => $values) {
            $result[trim(strtolower($name))] = $values;
        }
        return $result;
    }
}