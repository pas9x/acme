<?php

namespace pas9x\acme;

use Throwable;
use RuntimeException;
use LogicException;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use pas9x\acme\implementations\http\CurlRequest;
use pas9x\acme\exceptions\UnexpectedResponse;
use pas9x\acme\exceptions\AcmeError;

/**
 * @internal
 */
class ACME_internals
{
    /** @var ACME $acme */
    public $acme;

    /** @var null|string */
    public $lastNonce = null;

    /** @var null|RequestInterface */
    public $lastRequest = null;

    /** @var null|ResponseInterface */
    public $lastResponse = null;

    public function __construct(ACME $acme)
    {
        $this->acme = $acme;
    }

    public function httpRequest(RequestInterface $request)
    {
        $this->lastRequest = $request;
        $this->lastResponse = null;
        $this->lastResponse = $this->acme->httpClient()->sendRequest($request);

        $nonce = $this->responseHeader('Replay-Nonce');
        if ($nonce !== null && $nonce !== '') {
            $this->lastNonce = $nonce;
        }
    }

    public function responseHeader(string $name, bool $required = false): ?string
    {
        if (empty($this->lastResponse)) {
            throw new LogicException('responseHeader(): no http-response');
        }

        $nameL = strtolower($name);
        $header = $this->lastResponse->getHeader($nameL);
        $count = count($header);

        $contentType = $this->lastResponse->getHeader('content-type');
        if (count($contentType) === 1 && isset($contentType[0]) && is_string($contentType[0])) {
            $contentType = $contentType[0];
        } else {
            $contentType = null;
        }

        if ($count < 1) {
            if ($required) {
                $message = "No `$name` response header. responseCode=" . $this->lastResponse->getStatusCode();
                if (!empty($contentType)) $message .= ', contentType=' . $contentType;
                throw new UnexpectedResponse($message);
            } else {
                return null;
            }
        }

        if ($count === 1) {
            if (isset($header[0]) && is_string($header[0])) {
                return $header[0];
            } else {
                throw new LogicException('getHeader() result is invalid');
            }
        }

        throw new RuntimeException("HTTP response has multiple `$name` headers. Don't know which one to return.");
    }

    /**
     * @param string $url
     * @return array
     * @throws UnexpectedResponse
     */
    public function getDirectory(string $url): array
    {
        $request = new CurlRequest($url, 'GET', []);
        $this->httpRequest($request);
        $result = Utils::jsonDecode($this->lastResponse->getBody()->getContents());
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
        throw new RuntimeException("No directory item `$item`");
    }

    public function getNonce(): string
    {
        if ($this->lastNonce === null) {
            $url = $this->directoryItem('newNonce');
            $request = new CurlRequest($url, 'HEAD', []);
            $this->httpRequest($request);
            if ($this->lastNonce === null || $this->lastNonce === '') {
                throw new RuntimeException('Failed to acquire nonce');
            }
        }
        $result = $this->lastNonce;
        $this->lastNonce = null;
        return $result;
    }

    public function joseRequest(string $url, array $jose)
    {
        $headers = ['Content-Type' => 'application/jose+json'];
        $requestBody = Utils::jsonEncode($jose);
        $request = new CurlRequest($url, 'POST', $headers, $requestBody);
        $this->httpRequest($request);
    }

    public function parseResponse(bool $requireJson): ?array
    {
        if (empty($this->lastResponse)) {
            throw new LogicException('parseResponse(): no http-response');
        }

        $responseCode = $this->lastResponse->getStatusCode();
        $contentType = $this->responseHeader('Content-Type');
        try {
            $response = Utils::jsonDecode($this->lastResponse->getBody()->getContents());
        } catch (Throwable $e) {
            if (!$requireJson) {
                return null;
            }
            $message = 'Failed to parse http response as json. responseCode=' . $responseCode;
            if (!empty($contentType)) $message .= ', contentType=' . $contentType;
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
}