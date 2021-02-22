<?php

namespace pas9x\acme\implementations\http;

use \LogicException;

class Cloneable
{
    /**
     * @param array $properties
     * @return static
     */
    protected function withMany(array $properties)
    {
        $original = [];
        foreach ($properties as $property => $value) {
            if (!property_exists($this, $property)) {
                throw new LogicException('No such property: ' . $property);
            }
            $original[$property] = $value;
        }

        foreach ($properties as $property => $value) {
            $this->$property = $value;
        }

        $result = clone $this;

        foreach ($original as $property => $value) {
            $this->$property = $value;
        }

        return $result;
    }

    /**
     * @param string $property
     * @param mixed $value
     * @return static
     */
    protected function withOne(string $property, $value)
    {
        return $this->withMany([$property => $value]);
    }
}