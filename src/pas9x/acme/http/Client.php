<?php

namespace pas9x\acme\http;

use Psr\Http\Client\ClientInterface;

class Client
{
    public ?HttpRequest $lastRequest = null;
    public ?HttpResponse $lastResponse = null;
    public Worker $worker;

    public function __construct()
    {
        $this->useCurlWorker();
    }

    public function useCurlWorker()
    {
        $this->worker = new CurlWorker;
    }

    public function usePsrWorker(ClientInterface $client)
    {
        $this->worker = new PsrWorker($client);
    }

    public function request(HttpRequest $request): HttpResponse
    {
        $this->lastResponse = $this->worker->request($request);
        $this->lastRequest = $request;
        return $this->lastResponse;
    }
}