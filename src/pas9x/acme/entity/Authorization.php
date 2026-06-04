<?php

namespace pas9x\acme\entity;

use pas9x\acme\AuthorizedEntity;
use pas9x\acme\dto\OrderIdentifier;
use pas9x\acme\exceptions\AcmeError;

class Authorization extends AuthorizedEntity
{
    const STATUS_PENDING = 'pending';
    const STATUS_VALID = 'valid';
    const STATUS_INVALID = 'invalid';
    const STATUS_DEACTIVATED = 'deactivated'; // The authorization cancelled by client
    const STATUS_EXPIRED = 'expired';
    const STATUS_REVOKED = 'revoked'; // The authorization revoked by the ACME server

    /** @var Challenge[] $challenges */
    public array $challenges;

    public OrderIdentifier $identifier;
    public ?int $expires = null;
    public ?bool $wildcard = null;
    public ?AcmeError $error = null;

    protected function getRequiredAttributes(): array
    {
        return [
            'identifier',
            'challenges',
        ];
    }

    protected function setRawEntity(object $rawEntity): void
    {
        parent::setRawEntity($rawEntity);

        $identifier = $this->getAttribute('identifier');
        $this->identifier = new OrderIdentifier($identifier->type, $identifier->value);
        $this->expires = $this->optionalTime($this->getAttribute('expires'));

        $challenges = $this->getAttribute('challenges');
        $this->challenges = [];
        foreach ($challenges as $challenge) {
            $this->challenges[] = new Challenge($challenge->url, $challenge, $this->authorized);
        }

        $this->wildcard = $this->getAttribute('wildcard');
        $this->error = $this->optionalError($this->getAttribute('error'));
    }

    /**
     * @return string[]
     */
    public function getChallengeTypes(): array
    {
        $result = [];
        foreach ($this->challenges as $challenge) {
            $result[] = $challenge->type;
        }
        return $result;
    }

    public function getSpecificChallenge(string $type): ?Challenge
    {
        foreach ($this->challenges as $challenge) {
            if ($challenge->type === $type) {
                return $challenge;
            }
        }
        return null;
    }
}