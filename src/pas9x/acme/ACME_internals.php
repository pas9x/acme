<?php

namespace pas9x\acme;

use pas9x\acme\contracts\PrivateKey;
use pas9x\acme\contracts\Signer;
use Throwable;
use Exception;
use RuntimeException;
use pas9x\acme\dto\Event;
use pas9x\acme\contracts\HttpClient;
use pas9x\acme\contracts\HttpRequest;
use pas9x\acme\contracts\HttpResponse;
use pas9x\acme\contracts\HttpWatcher;
use pas9x\acme\exceptions\UnexpectedResponse;
use pas9x\acme\exceptions\HttpException;
use pas9x\acme\exceptions\AcmeError;

/**
 * @internal
 */
class ACME_internals implements HttpWatcher
{
    /** @var ACME $acme */
    public $acme;

    /** @var null|string */
    public $lastNonce = null;

    /** @var EventListener[] */
    public $eventListeners = [];

    public function __construct(ACME $acme)
    {
        $this->acme = $acme;
    }

    /**
     * @param string $url
     * @return array
     * @throws UnexpectedResponse
     * @throws HttpException
     */
    public function getDirectory(string $url): array
    {
        $response = $this->acme->httpClient()->get($url);
        $result = Utils::jsonDecode($response->body());
        if (is_array($result)) {
            return $result;
        } else {
            throw new UnexpectedResponse;
        }
    }

    public function directoryItem(string $item, $defaultValue = null)
    {
        $directory = $this->acme->directory();
        if (array_key_exists($item, $directory)) {
            return $directory[$item];
        }
        if (func_num_args() > 1) {
            return $defaultValue;
        }
        throw new Exception("No directory item `$item`");
    }

    public function getNonce(): string
    {
        if ($this->lastNonce === null) {
            $url = $this->directoryItem('newNonce');
            $this->acme->httpClient()->request($url, 'HEAD');
            if ($this->lastNonce === null || $this->lastNonce === '') {
                throw new RuntimeException('Failed to acquire nonce');
            }
        }
        $result = $this->lastNonce;
        $this->lastNonce = null;
        return $result;
    }

    public function responseHeader(string $name, bool $required = false): ?string
    {
        $name = strtolower($name);
        $response = $this->acme->httpClient()->lastResponse();
        if (!isset($response->__headers)) {
            $response->__headers = [];
            foreach ($response->headers() as $currentName => $currentValues) {
                $currentName = trim(strtolower($currentName));
                if ($currentName === '') continue;
                foreach ($currentValues as $currentValue) {
                    $response->__headers[$currentName][] = trim($currentValue);
                }
            }
        }
        if (!isset($response->__headers[$name])) {
            if ($required === true) {
                $message = "No `$name` response header. httpCode=" . $response->code();
                $contentType = $this->responseHeader('Content-Type');
                if (!empty($contentType)) $message .= ', contentType=' . $contentType;
                throw new UnexpectedResponse($message);
            } else {
                return null;
            }
        }
        if (count($response->__headers[$name]) > 1) {
            throw new RuntimeException("HTTP response has multiple `$name` headers. Don't know which one to return.");
        }
        return $response->__headers[$name][0];
    }

    public function onRequest(HttpRequest $request, HttpClient $httpClient)
    {
        $this->emitEvent(Event::E_HTTP_REQUEST, $request);
    }

    public function onResponse(HttpResponse $response, HttpClient $httpClient)
    {
        $nonce = $this->responseHeader('Replay-Nonce');
        if ($nonce !== null && $nonce !== '') {
            $this->lastNonce = $nonce;
        }
        $this->emitEvent(Event::E_HTTP_RESPONSE, $response);
    }

    public function joseRequest(string $url, array $jose)
    {
        $headers = ['Content-Type' => 'application/jose+json'];
        $requestBody = Utils::jsonEncode($jose);
        $this->acme->httpClient()->post($url, $requestBody, $headers);
    }

    public function parseResponse(bool $requireJson): ?array
    {
        $response = $this->acme->httpClient()->lastResponse();
        $responseCode = $response->code();
        $contentType = $this->responseHeader('Content-Type');
        try {
            $response = Utils::jsonDecode($response->body());
        } catch (Throwable $e) {
            if (!$requireJson) {
                return null;
            }
            $message = 'Failed to parse http response as json. responseCode=' . $responseCode;
            if (!empty($contentType)) {
                $message .= ', contentType=' . $contentType;
            }
            $message .= ', jsonError=' . $e->getMessage();
            throw new UnexpectedResponse($message);
        }
        if (!is_array($response)) {
            if ($requireJson) {
                throw new UnexpectedResponse('Unexpected type of jsonDecode() result: ' . gettype($response));
            } else {
                return null;
            }
        }
        if (isset($response['type']) && ($responseCode >= 400 || $contentType === 'application/problem+json')) {
            $type = $response['type'];
            $detail = $response['detail'] ?? null;
            throw new AcmeError($type, $detail, $responseCode, $response);
        }
        return $response;
    }

    public function emitEvent(string $code, $details = null): Event
    {
        $event = new Event($code, $details);
        foreach ($this->eventListeners as $eventListener) {
            $eventListener->onEvent($event);
        }
        return $event;
    }
}