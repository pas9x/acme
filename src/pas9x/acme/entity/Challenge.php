<?php

namespace pas9x\acme\entity;

use pas9x\acme\exceptions\AcmeError;
use pas9x\acme\exceptions\UnexpectedResponse;

class Challenge extends Entity
{
    /** @var Account $account */
    protected $account;

    /** @var string $type */
    protected $type;

    public function __construct($entityUrl, array $rawEntity, Account $account)
    {
        parent::__construct($entityUrl, $rawEntity);
        $this->account = $account;
        $this->refresh($rawEntity);
    }

    public function token(): ?string
    {
        return $this->getAttribute('token', null);
    }

    public function validated(): ?int
    {
        $time = $this->getAttribute('validated', null);
        if ($time === null) {
            return null;
        }
        $result = strtotime($time);
        if (is_int($result)) {
            return $result;
        } else {
            throw new UnexpectedResponse('Failed to parse `validated` attribute as time', $this->raw());
        }
    }

    public function error(): ?AcmeError
    {
        $rawError = $this->getAttribute('error', null);
        if ($rawError === null) {
            return null;
        }
        return new AcmeError($rawError['type'], $rawError['detail'], null, $rawError);
    }

    public function validate()
    {
        $this->account->internals()->joseRequest($this->url(), new \stdClass);
        $rawEntity = $this->account->acme()->internals()->parseResponse(true);
        $this->refresh($rawEntity);
    }

    public function refresh(array $rawEntity = null)
    {
        if ($rawEntity === null) {
            $rawEntity = $this->account->internals()->getRawEntity($this->url());
        }

        $type = $this->getAttribute('type');

        if ($this->construct) {
            $this->construct = false;
        } else {
            $this->setRawEntity($rawEntity);
        }

        $this->type = $type;
    }

    /** @return string[] */
    protected function requiredAttributes(): array
    {
        return [
            'type',
        ];
    }
}