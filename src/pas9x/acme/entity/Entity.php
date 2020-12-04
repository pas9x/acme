<?php

namespace pas9x\acme\entity;

use LogicException;
use pas9x\acme\exceptions\UnexpectedResponse;

abstract class Entity
{
    /** @var string $entityUrl */
    private $entityUrl;

    /** @var array $rawEntity */
    private $rawEntity;

    private $entityType;

    protected $construct = true; // Small duct tape to prevent double setRawEntity() in constructor

    /** @return string[] */
    protected abstract function requiredAttributes(): array;

    public abstract function refresh(array $rawEntity = null);

    public function __construct(string $entityUrl, array $rawEntity)
    {
        $this->entityUrl = $entityUrl;

        $className = get_class($this);
        $this->entityType = preg_match('/\\\([^\\\]+)$/', $className, $matches) ? $matches[1] : $className;

        $this->setRawEntity($rawEntity);
    }

    public function entityType(): string
    {
        return $this->entityType;
    }

    public function url(): string
    {
        return $this->entityUrl;
    }

    public function status(): string
    {
        return $this->rawEntity['status'];
    }

    public function raw(): array
    {
        return $this->rawEntity;
    }

    public function hasAttribute(string $name): bool
    {
        return array_key_exists($name, $this->rawEntity);
    }

    public function getAttribute(string $name, $defaultValue = null)
    {
        if ($this->hasAttribute($name)) {
            return $this->rawEntity[$name];
        }
        if (func_num_args() > 1) {
            return $defaultValue;
        }
        throw new LogicException('Entity ' . $this->entityType() . ' has no `' . $name . '` attribute`');
    }

    protected function setRawEntity(array $rawEntity)
    {
        if (!isset($rawEntity['status'])) {
            throw new UnexpectedResponse($this->entityType() . '->setRawEntity() failed: no $rawEntity[status]');
        }
        if (!is_string($rawEntity['status'])) {
            throw new UnexpectedResponse($this->entityType() . '->setRawEntity() failed: invalid type of $rawEntity[status]: ' . gettype($rawEntity['status']));
        }
        foreach ($this->requiredAttributes() as $attributeName) {
            if (!isset($rawEntity[$attributeName])) {
                throw new UnexpectedResponse($this->entityType() . '->setRawEntity() failed: No $info[' . $attributeName . '] attribute in $rawEntity');
            }
        }
        $this->rawEntity = $rawEntity;
    }
}