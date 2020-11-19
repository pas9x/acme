<?php

namespace pas9x\letsencrypt;

use \Exception;

class Order extends StatusBasedObject
{
    protected function getObjectType()
    {
        return 'order';
    }

    protected function requiredAttributes()
    {
        return [
            'identifiers',
            'finalize',
        ];
    }

    /**
     * @return Authorization[]
     * @throws Exception
     */
    public function getAuthorizations()
    {
        if (!isset($this->info['authorizations'])) {
            throw new Exception('No authorizations in order');
        }
        $result = [];
        foreach ($this->info['authorizations'] as $authzUrl) {
            $authz = $this->internals->getAuthorization($authzUrl);
            $result[] = $authz;
        }
        return $result;
    }

    /** @return VerificationData[] */
    public function getDomainsVerificationData()
    {
        $result = [];
        $thumbprint_b64 = LetsEncryptInternals::b64_urlencode($this->internals->le->accountKeys->thumbprint());
        foreach ($this->getAuthorizations() as $authz) {
            $authzDomain = $authz->getAttribute('identifier')['value'];
            $verificationData = new VerificationData;
            foreach ($authz->getChallenges() as $challenge) {
                $keyAuthorization = $challenge->getAttribute('token') . '.' . $thumbprint_b64;
                $challengeType = $challenge->getAttribute('type');
                if ($challengeType === 'http-01') {
                    $verificationData->fileUri = '/.well-known/acme-challenge/' . $challenge->getAttribute('token');
                    $verificationData->fileContent = $keyAuthorization;
                } elseif ($challengeType === 'dns-01') {
                    $verificationData->txtRecord = LetsEncryptInternals::sha256($keyAuthorization, 'b64url');
                }
            }
            $result[$authzDomain] = $verificationData;
        }
        return $result;
    }

    /**
     * Step 1
     * @param string|Challenge[] Challenge type string (e.g. http-01, dns-01) or custom list of challenges.
     * @throws Exception
     */
    public function startDomainsVerification($challengeType)
    {
        $status = $this->getStatus();
        if ($status === 'ready') {
            return;
        }
        if ($status !== 'pending') {
            throw new Exception("Cannot ask for verification. Only `pending` status is suitable for verification. Order status is `$status`.");
        }

        if (is_string($challengeType)) {
            foreach ($this->getAuthorizations() as $authz) {
                $authzStatus = $authz->getStatus();
                $authzDomain = $authz->getDomain();
                if ($authzStatus === 'valid') {
                    continue;
                }
                if ($authzStatus === 'expired') {
                    throw new Exception("Authorization for domain `$authzDomain` is expired. You can start new order.");
                }
                $selectedChallenge = null;
                foreach ($authz->getChallenges() as $challenge) {
                    if ($challenge->getType() === $challengeType) {
                        $selectedChallenge = $challenge;
                        break;
                    }
                }
                if (empty($selectedChallenge)) {
                    throw new Exception("No challenge with `$challengeType` verification method for domain `$authzDomain`");
                }
                $selectedChallenge->validate();
            }
        } elseif (is_array($challengeType)) {
            foreach ($challengeType as $index => $challenge) {
                if ($challenge instanceof Challenge) {
                    $challenge->validate();
                } else {
                    throw new Exception("Invalid value of \$challengeType[{$index}]");
                }
            }
        } else {
            throw new Exception('Invalid type of $challengeType argument: ' . gettype($challengeType));
        }
    }

    /**
     * Step 2
     * @param bool $update
     * @return bool
     * @throws Exception
     */
    public function isReadyToCertificateRegistration($update = true)
    {
        if ($update) {
            $this->refresh();
        }
        $status = $this->getStatus();
        if ($status === 'pending') {
            return false;
        }
        if ($status === 'ready') {
            return true;
        }
        throw new Exception("Status of this order is `$status`. You cannot continue to register this certificate.");
    }

    /**
     * Step 3
     * @param $primaryDomain
     * @param $email
     * @param array $distinguishedNameFields
     * @throws Exception
     * @throws UnexpectedResponse
     * @return CSR
     */
    public function commitCertificateRegistration(
        $primaryDomain,
        $email,
        $distinguishedNameFields = []
    )
    {
        $status = $this->getStatus();
        if ($status !== 'ready') {
            throw new Exception("Status of this order is `$status`. You can register certificate only when status is `ready`.");
        }

        $additionalDomains = [];
        if (!empty($this->info['identifiers'])) foreach ($this->info['identifiers'] as $identifier) {
            if (empty($identifier['value'])) {
                throw new UnexpectedResponse('No value in identifier object (2)');
            }
            if ($identifier['value'] !== $primaryDomain) {
                $additionalDomains[] = $identifier['value'];
            }
        }

        $csr = LetsEncryptInternals::generateCSR(null, $email, $primaryDomain, $additionalDomains, [], $distinguishedNameFields);
        $payload = [
            'csr' => LetsEncryptInternals::b64_urlencode($csr->der),
        ];
        $this->internals->sendRequest($this->getAttribute('finalize'), 'kid', $payload);
        $response = $this->internals->getResponse();
        $orderUpdated = new static($this->internals, $this->url, $response);
        $this->refresh($orderUpdated);
        return $csr;
    }

    public function isRegistrationComplete($update = true)
    {
        if ($update) {
            $this->refresh();
        }
        $status = $this->getStatus();
        if ($status === 'processing') {
            return false;
        }
        if ($status === 'valid') {
            return true;
        }
        throw new Exception("Status of this order is `$status`. You cannot continue to register this certificate.");
    }

    /**
     * @return string[]
     * @throws Exception
     * @throws UnexpectedResponse
     */
    public function downloadCertificate()
    {
        $status = $this->getStatus();
        if ($status !== 'valid') {
            throw new Exception("Status of this order is `$status`. Downloading certificate is possible only when order status is `valid`.");
        }
        $certificateUrl = $this->getAttribute('certificate');
        $this->internals->sendRequest($certificateUrl, 'kid');
        $this->internals->checkForError();
        $response = $this->internals->le->lastRequest->responseBody;
        try {
            $certificateChain = LetsEncryptInternals::parseCertificateChain($response);
        } catch (Exception $e) {
            throw new UnexpectedResponse('Failed to parse response as chain of certificate PEMs. http_code=' . $this->internals->le->lastRequest->responseCode);
        }
        if (!LetsEncryptInternals::checkCertificateChain($certificateChain)) {
            throw new UnexpectedResponse('Certificate chain is invalid');
        }
        return $certificateChain;
    }

    /**
     * @return Authorization[]
     * @throws Exception
     */
    public function deactivateVerification()
    {
        $result = [];
        foreach ($this->getAuthorizations() as $authz) {
            $authz->deactivate();
            $result[$authz->getDomain()] = $authz;
        }
        return $result;
    }
}