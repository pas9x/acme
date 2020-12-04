<?php

namespace pas9x\acme\contracts;

use pas9x\acme\exceptions\HttpException;
use pas9x\acme\contracts\HttpWatcher;

interface HttpClient
{
    /**
     * @param string $url
     * @param string[] $headers
     * @throws HttpException
     * @return HttpResponse
     */
    public function get(string $url, array $headers = []): HttpResponse;

    /**
     * @param string $url
     * @param null|array|string $postdata
     * @param string[] $headers
     * @throws HttpException
     * @return HttpResponse
     */
    public function post(string $url, $postdata = null, array $headers = []): HttpResponse;

    /**
     * @param string $url
     * @param string $method
     * @param array $headers
     * @param null $body
     * @throws HttpException
     * @return HttpResponse
     */
    public function request(string $url, string $method, array $headers = [], $body = null): HttpResponse;

    /**
     * @return HttpRequest|null
     */
    public function lastRequest(): ?HttpRequest;

    /**
     * @return HttpResponse|null
     */
    public function lastResponse(): ?HttpResponse;

    /**
     * @param HttpWatcher $watcher
     */
    public function addWatcher(HttpWatcher $watcher);
}