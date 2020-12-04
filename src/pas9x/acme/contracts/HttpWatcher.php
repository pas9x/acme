<?php

namespace pas9x\acme\contracts;

interface HttpWatcher
{
    public function onRequest(HttpRequest $request, HttpClient $client);
    public function onResponse(HttpResponse $response, HttpClient $httpClient);
}