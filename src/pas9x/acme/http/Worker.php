<?php

namespace pas9x\acme\http;

interface Worker
{
    public function request(HttpRequest $request): HttpResponse;
}