<?php

namespace test;

use pas9x\acme\ACME;
use Psr\Http\Client\ClientInterface;

trait AcmeTest_acme
{
    protected ?ACME $acme = null;
    protected ?ClientInterface $guzzleHttpClient = null;
    protected ?ClientInterface $symfonyHttpClient = null;

    protected function getGuzzleHttpClient(): ClientInterface
    {
        if ($this->guzzleHttpClient === null) {
            $this->guzzleHttpClient = new \GuzzleHttp\Client;
        }
        return $this->guzzleHttpClient;
    }

    protected function getSymfonyHttpClient(): ClientInterface
    {
        if ($this->symfonyHttpClient === null) {
            $symfonyClient = \Symfony\Component\HttpClient\HttpClient::create();
            $this->symfonyHttpClient = new \Symfony\Component\HttpClient\Psr18Client($symfonyClient);
        }
        return $this->symfonyHttpClient;
    }

    public function getACME(): ACME
    {
        if ($this->acme === null) {
            $this->acme = new ACME($this->ca->directoryUrl);
        }

        $choice = rand(1, 3);
        if ($choice === 1) {
            $this->acme->httpClient->useCurlWorker();
        } elseif ($choice === 2) {
            $this->acme->httpClient->usePsrWorker($this->getSymfonyHttpClient());
        } elseif ($choice === 3) {
            $this->acme->httpClient->usePsrWorker($this->getSymfonyHttpClient());
        } else {
            throw new \LogicException;
        }

        return $this->acme;
    }
}