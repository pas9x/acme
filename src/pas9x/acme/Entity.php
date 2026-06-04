<?php

namespace pas9x\acme;

use pas9x\acme\exceptions\AcmeError;

abstract class Entity
{
    public string $status;

    protected object $rawEntity;
    protected readonly string $entityType;

    /**
     * @return string[]
     */
    protected abstract function getRequiredAttributes(): array;

    public function __construct(protected readonly string $entityUrl, object $rawEntity)
    {
        $className = get_class($this);
        $parts = explode('\\', $className);
        $this->entityType = end($parts);
        $this->setRawEntity($rawEntity);
    }

    public function getEntityUrl(): string
    {
        return $this->entityUrl;
    }

    public function getEntityType(): string
    {
        return $this->entityType;
    }

    public function getRawEntity(): object
    {
        return $this->rawEntity;
    }

    protected function getAttribute(string $attribute, mixed $default = null): mixed
    {
        return $this->rawEntity->$attribute ?? $default;
    }

    protected function setRawEntity(object $rawEntity): void
    {
        $baseAttributes = [
            'status',
        ];
        $requiredAttributes = array_merge($baseAttributes, $this->getRequiredAttributes());

        foreach ($requiredAttributes as $attribute) {
            if (!property_exists($rawEntity, $attribute)) {
                $message = "Failed to fill {$this->entityType} entity. Raw entity json have no required `{$attribute}` attribute.";
                throw new \InvalidArgumentException($message);
            }
        }

        $this->status = $rawEntity->status;
        $this->rawEntity = $rawEntity;
    }

    protected function optionalError(?object $error): ?AcmeError
    {
        if (empty($error)) {
            return null;
        }
        if (!isset($error->type)) {
            return null;
        }
        return new AcmeError($error->type, $error->detail ?? null, null, $error);
    }

    protected function optionalTime(?string $time): ?string
    {
        if (empty($time)) {
            return null;
        }
        $timestamp = @strtotime($time);
        if (!is_int($timestamp)) {
            return null;
        }
        return $timestamp;
    }
}