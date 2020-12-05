<?php

namespace pas9x\acme\entity;

use pas9x\acme\dto\OrderIdentifier;

class Order extends Entity
{
    protected $account;

    /** @var OrderIdentifier[] */
    protected $identifiers = [];

    /** @var int|null */
    protected $notBefore = null;

    /** @var int|null */
    protected $notAfter = null;

    /** @var array $authorizations */
    protected $authorizations = null;

    public function __construct(string $entityUrl, array $rawEntity, Account $account)
    {
        parent::__construct($entityUrl, $rawEntity);
        $this->account = $account;
        $this->refresh($rawEntity);
    }

    /** @return OrderIdentifier[] */
    public function identifiers(): array
    {
        return $this->identifiers;
    }

    public function notBefore(): ?int
    {
        return $this->notBefore;
    }

    public function notAfter(): ?int
    {
        return $this->notAfter;
    }

    /**
     * @param bool $useCache
     * @return Authorization[]
     */
    public function authorizations(bool $useCache = true): array
    {
        if ($this->authorizations === null || !$useCache) {
            $authorizations = [];
            foreach ($this->getAttribute('authorizations') as $authorizationUrl) {
                $authorizations[] = $this->account->getAuthorization($authorizationUrl);
            }
            $this->authorizations = $authorizations;
        }
        return $this->authorizations;
    }

    public function refresh(array $rawEntity = null)
    {
        if ($rawEntity === null) {
            $rawEntity = $this->account->internals()->getRawEntity($this->url());
        }

        $identifiers = [];
        $notBefore = null;
        $notAfter = null;

        foreach ($rawEntity['identifiers'] as $identifier) {
            $identifiers[] = new OrderIdentifier($identifier['type'], $identifier['value']);
        }
        if (!empty($rawEntity['notBefore'])) {
            $notBefore = strtotime($rawEntity['notBefore']);
            if (!is_int($notBefore)) $notBefore = null;
        }
        if (!empty($rawEntity['notAfter'])) {
            $notAfter = strtotime($rawEntity['notAfter']);
            if (!is_int($notAfter)) $notAfter = null;
        }

        if ($this->construct) {
            $this->construct = false;
        } else {
            $this->setRawEntity($rawEntity);
        }

        $this->identifiers = $identifiers;
        $this->notBefore = $notBefore;
        $this->notAfter = $notAfter;
        $this->authorizations = null;
    }

    /** @return string[] */
    protected function requiredAttributes(): array
    {
        return [
            'identifiers',
            'authorizations',
            'finalize',
        ];
    }
}