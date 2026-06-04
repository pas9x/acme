<?php

namespace pas9x\acme;

use pas9x\acme\http\HttpRequest;
use pas9x\acme\http\HttpResponse;
use pas9x\acme\exceptions\UnexpectedResponse;
use pas9x\acme\exceptions\AcmeError;

/**
 * @internal
 */
class ACME_internals
{
    public ?string $lastNonce = null;
    public int $lastNonceTime = 0;
    public ?HttpRequest $lastRequest = null;
    public ?HttpResponse $lastResponse = null;
    public int $nonceLifetime = 60;

    public function __construct(public readonly ACME $acme)
    {
    }

    public function httpRequest(HttpRequest $request): void
    {
        $this->lastRequest = $request;
        $this->lastResponse = null;
        $this->lastResponse = $this->acme->httpClient->request($request);
        $nonce = $this->responseHeader('Replay-Nonce');
        if ($nonce !== null && $nonce !== '') {
            $this->lastNonce = $nonce;
            $this->lastNonceTime = time();
        }
    }

    public function responseHeader(string $name, bool $required = false): ?string
    {
        if (empty($this->lastResponse)) {
            throw new \LogicException('responseHeader(): no http-response');
        }

        $value = $this->lastResponse->header($name);
        $contentType = $this->lastResponse->contentType;

        if ($value !== null) {
            return $value;
        }

        if ($required) {
            $message = "No `$name` response header. responseCode=" . $this->lastResponse->code;
            if (!empty($contentType)) $message .= ', contentType=' . $contentType;
            throw new UnexpectedResponse($message);
        } else {
            return null;
        }
    }

    public function getDirectory(string $url): object
    {
        $request = new HttpRequest($url);
        $this->httpRequest($request);
        $result = Utils::jsonDecode($this->lastResponse->body);
        if (is_object($result)) {
            return $result;
        } else {
            throw new UnexpectedResponse;
        }
    }

    public function getDirectoryItem(string $item, mixed $defaultValue = null): mixed
    {
        $directory = $this->acme->getDirectory();
        if (property_exists($directory, $item)) {
            return $directory->$item;
        }
        if (func_num_args() > 1) {
            return $defaultValue;
        }
        throw new \RuntimeException("No directory item `$item`");
    }

    public function getNonce(): string
    {
        $nonceAge = time() - $this->lastNonceTime;
        if ($this->lastNonce === null || $nonceAge > $this->nonceLifetime) {
            $this->lastNonce = null;
            $this->lastNonceTime = 0;
            $url = $this->getDirectoryItem('newNonce');
            $request = new HttpRequest($url, 'HEAD');
            $this->httpRequest($request);
            if ($this->lastNonce === null || $this->lastNonce === '') {
                throw new \RuntimeException('Failed to acquire nonce');
            }
        }
        $result = $this->lastNonce;
        $this->lastNonce = null;
        $this->lastNonceTime = 0;
        return $result;
    }

    public function joseRequest(string $url, object $jose): void
    {
        $headers = ['Content-Type' => 'application/jose+json'];
        $requestBody = Utils::jsonEncode($jose);
        $request = new HttpRequest($url, 'POST', $headers, $requestBody);
        $this->httpRequest($request);
    }

    public function parseResponse(bool $requireJson): ?object
    {
        if (empty($this->lastResponse)) {
            throw new \LogicException('parseResponse(): no http-response');
        }

        $responseCode = $this->lastResponse->code;
        $contentType = $this->lastResponse->contentType;
        try {
            $response = Utils::jsonDecode($this->lastResponse->body);
        } catch (\Throwable $e) {
            if (!$requireJson) {
                return null;
            }
            $message = 'Failed to parse http response as json. responseCode=' . $responseCode;
            if (!empty($contentType)) $message .= ', contentType=' . $contentType;
            $message .= ', jsonError=' . $e->getMessage();
            throw new UnexpectedResponse($message);
        }
        if (!is_object($response)) {
            if ($requireJson) {
                throw new UnexpectedResponse('Unexpected type of jsonDecode() result: ' . gettype($response));
            } else {
                return null;
            }
        }
        if (isset($response->type) && ($responseCode >= 400 || $contentType === 'application/problem+json')) {
            $type = $response->type;
            $detail = $response->detail ?? null;
            throw new AcmeError($type, $detail, $responseCode, $response);
        }
        return $response;
    }
}