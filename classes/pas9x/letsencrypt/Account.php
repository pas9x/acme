<?php

namespace pas9x\letsencrypt;

use \Exception;

class Account extends StatusBasedObject
{
    protected function getObjectType()
    {
        return 'account';
    }

    protected function requiredAttributes()
    {
        return [];
    }

    public function save($email)
    {
        $newFields = [
            'contact' => [
                "mailto:$email",
            ],
        ];
        $accountUpdated = $this->entrails->saveAccount($newFields);
        $this->refresh($accountUpdated);
    }

    public function keyChange(KeyPair $newKeys)
    {
        $oldKeys = $this->entrails->le->accountKeys;
        $this->entrails->le->accountKeys = $newKeys;

        $subpayloadConfig = [
            'format' => 'b64json',
            'payload' => [
                'account' => $this->entrails->le->accountUrl,
                'oldKey' => $oldKeys->getJwk(),
            ],
        ];

        $keyChangeUrl = $this->entrails->le->getDirectory('keyChange');
        $payload = $this->entrails->formatRequest($keyChangeUrl, 'jwk', $subpayloadConfig);
        $this->entrails->le->accountKeys = $oldKeys;
        $this->entrails->postWithPayload($keyChangeUrl, $payload, 'kid');

        $response = $this->entrails->getResponse();
        $this->refresh($response);
        $this->entrails->le->accountKeys = $newKeys;
    }

    public function deactivate()
    {
        $newFields = [
            'status' => 'deactivated',
        ];
        $accountUpdated = $this->entrails->saveAccount($newFields);
        $this->refresh($accountUpdated);
    }
}