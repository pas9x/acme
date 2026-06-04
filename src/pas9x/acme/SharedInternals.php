<?php

namespace pas9x\acme;

/**
 * @internal
 */
trait SharedInternals
{
    protected ?ACME_internals $internals = null;

    protected function getInternals(object $object): void
    {
        $refObject = new \ReflectionObject($object);
        if (!$refObject->hasProperty('internals')) {
            throw new \LogicException('Getting internals failed');
        }
        $refProperty = $refObject->getProperty('internals');
        //$refProperty->setAccessible(true);
        $internals = $refProperty->getValue($object);
        if ($internals instanceof ACME_Internals) {
            $this->internals = $internals;
        } else {
            throw new \LogicException('Invalid type of internals: ' . Utils::gettype($internals));
        }
    }
}