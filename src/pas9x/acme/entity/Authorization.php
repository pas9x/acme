<?php

namespace pas9x\acme\entity;

use pas9x\acme\dto\OrderIdentifier;

class Authorization extends Entity
{
    /** @var OrderIdentifier $identifier */
    protected $identifier;

    /** @var Account $order */
    protected $account;

    /** @var Challenge[] */
    protected $challenges = null;

    public function __construct(string $entityUrl, array $rawEntity, Account $account)
    {
        parent::__construct($entityUrl, $rawEntity);
        $this->refresh($rawEntity);
        $this->account = $account;
    }

    public function identifier(): OrderIdentifier
    {
        return $this->identifier;
    }

    /**
     * @param bool $useCache
     * @return Challenge[]
     */
    public function challenges(bool $useCache = true): array
    {
        if ($this->challenges === null || !$useCache) {
            $challenges = [];
            foreach ($this->getAttribute('challenges') as $challenge) {
                $challenges[] = $this->account->getChallenge($challenge['url']);
            }
            $this->challenges = $challenges;
        }
        return $this->challenges;
    }

    public function refresh(array $rawEntity = null)
    {
        if ($rawEntity === null) {
            $rawEntity = $this->account->internals()->getRawEntity($this->url());
        }

        $identifier = new OrderIdentifier($rawEntity['identifier']['type'], $rawEntity['identifier']['value']);

        if ($this->construct) {
            $this->construct = false;
        } else {
            $this->setRawEntity($rawEntity);
        }

        $this->identifier = $identifier;
        $this->challenges = null;
    }

    /** @return string[] */
    protected function requiredAttributes(): array
    {
        return [
            'identifier',
            'challenges',
        ];
    }
}