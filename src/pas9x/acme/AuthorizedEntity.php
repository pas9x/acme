<?php

namespace pas9x\acme;

abstract class AuthorizedEntity extends Entity
{
    use SharedInternals;

    public function __construct(string $url, object $rawEntity, protected readonly Authorized $authorized)
    {
        parent::__construct($url, $rawEntity);
        $this->getInternals($this->authorized);
    }

    public function refresh(): void
    {
        $this->authorized->executeAuthorizedRequest($this->entityUrl);
        $rawEntity = $this->internals->parseResponse(true);
        $this->setRawEntity($rawEntity);
    }
}