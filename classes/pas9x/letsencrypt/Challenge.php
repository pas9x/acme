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
        $this->entrails->postWithPayload($this->url, $payload, 'kid');
        $response = LetsEncryptEntrails::jsonDecode($this->entrails->le->lastRequest->responseBody);
        $challengeUpdated = new static($this->entrails, $this->url, $response);
        $this->refresh($challengeUpdated);
    }
}