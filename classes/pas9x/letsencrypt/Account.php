<?php

namespace pas9x\letsencrypt;

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
        $accountUpdated = $this->internals->saveAccount($newFields);
        $this->refresh($accountUpdated);
    }

    public function keyChange(KeyPair $newKeys)
    {
        $oldKeys = $this->internals->le->accountKeys;
        $this->internals->le->accountKeys = $newKeys;

        $subpayloadConfig = [
            'account' => $this->internals->le->accountUrl,
            'oldKey' => $oldKeys->getJwk(),
        ];

        $keyChangeUrl = $this->internals->le->getDirectory('keyChange');
        $payload = $this->internals->formatRequest($keyChangeUrl, 'jwk', $subpayloadConfig);
        $this->internals->le->accountKeys = $oldKeys;
        $this->internals->sendRequest($keyChangeUrl, 'kid', $payload);

        $response = $this->internals->getResponse();
        $this->refresh($response);
        $this->internals->le->accountKeys = $newKeys;
    }

    public function deactivate()
    {
        $newFields = [
            'status' => 'deactivated',
        ];
        $accountUpdated = $this->internals->saveAccount($newFields);
        $this->refresh($accountUpdated);
    }
}