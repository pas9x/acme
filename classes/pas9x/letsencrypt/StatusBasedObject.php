<?php

namespace pas9x\letsencrypt;

use \Exception;

abstract class StatusBasedObject
{
    /** @var LetsEncryptEntrails $entrails */
    public $entrails;

    /** @var string $url */
    public $url;

    /** @var array $info */
    public $info = [];

    public final function __construct(LetsEncryptEntrails $entrails, $url, array $info)
    {
        if (!isset($info['status'])) {
            throw new UnexpectedResponse('No $info[status] field. It is not an ' . $this->getObjectType() . ' object.');
        }
        if (!empty($this->requireFields)) {
            foreach ($this->requiredAttributes() as $attributeName) {
                if (!isset($info[$attributeName])) {
                    throw new UnexpectedResponse('No $info[' . $attributeName . '] field in ' . $this->getObjectType() . ' object.');
                }
            }
        }
        $this->entrails = $entrails;
        $this->url = $url;
        $this->info = $info;
        if (method_exists($this, 'construct1')) {
            $this->construct1();
        }
    }

    public function getAttribute($name)
    {
        if (isset($this->info[$name])) {
            return $this->info[$name];
        } else {
            throw new Exception(lcfirst($this->getObjectType()) . " has no `$name` attribute");
        }
    }

    public function getStatus()
    {
        return $this->getAttribute('status');
    }

    /**
     * @param null|array|static $newInfo
     * @throws Exception
     */
    public function refresh($newInfo = null)
    {
        if ($newInfo instanceof static) {
            if ($newInfo->url !== $this->url) {
                $objectType = $this->getObjectType();
                throw new Exception("New $objectType url isn't equal current $objectType url");
            }
            $this->info = $newInfo->info;
        } elseif (is_array($newInfo)) {
            $newObject = new static($this->entrails, $this->url, $newInfo);
            $this->info = $newObject->info;
        } elseif ($newInfo === null) {
            $tmpObject = $this->entrails->getObject(get_class($this), $this->url);
            $this->info = $tmpObject->info;
        } else {
            throw new Exception('Invalid value of $newInfo argument');
        }
    }

    /** @return string */
    protected abstract function getObjectType();

    /** @return array */
    protected abstract function requiredAttributes();
}