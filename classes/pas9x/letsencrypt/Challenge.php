<?php

namespace pas9x\letsencrypt;

use \Exception;

class Challenge extends StatusBasedObject
{
    protected function getObjectType()
    {
        return 'challenge';
    }

    protected function requiredAttributes()
    {
        return [];
    }

    public function getType()
    {
        return $this->getAttribute('type');
    }

    public function validate()
    {
        $payload = new \stdClass;
        $this->internals->sendRequest($this->url, 'kid', $payload);
        $response = LetsEncryptInternals::jsonDecode($this->internals->le->lastRequest->responseBody);
        $challengeUpdated = new static($this->internals, $this->url, $response);
        $this->refresh($challengeUpdated);
    }
}