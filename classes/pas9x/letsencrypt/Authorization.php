<?php

namespace pas9x\letsencrypt;

use \Exception;

class Authorization extends StatusBasedObject
{
    protected function getObjectType()
    {
        return 'authorization';
    }

    protected function requiredAttributes()
    {
        return [];
    }

    /**
     * @return Challenge[]
     * @throws Exception
     */
    public function getChallenges()
    {
        if (!isset($this->info['challenges'])) {
            throw new Exception('No challenges in authorization');
        }
        $result = [];
        foreach ($this->info['challenges'] as $challengeInfo) {
            if (empty($challengeInfo['url'])) {
                throw new Exception('Challenge has no url');
            }
            $result[] = new Challenge($this->entrails, $challengeInfo['url'], $challengeInfo);
        }
        return $result;
    }

    public function getChallenge($type)
    {
        $challenges = $this->getChallenges();
        foreach ($challenges as $challenge) {
            if ($challenge->getType() === $type) {
                return $challenge;
            }
        }
        return null;
    }

    public function getDomain()
    {
        $identifier = $this->getAttribute('identifier');
        if (empty($identifier['value'])) {
            throw new UnexpectedResponse('No value in identifier object (1)');
        } else {
            return $identifier['value'];
        }
    }

    public function deactivate()
    {
        $this->entrails->postWithPayload($this->url, ['status' => 'deactivated'], 'kid');
        $response = $this->entrails->getResponse();
        $authorizationUpdated = new Authorization($this->entrails, $this->url, $response);
        $this->refresh($authorizationUpdated);
    }
}