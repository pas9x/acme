<?php

namespace pas9x\acme\entity;

use pas9x\acme\AuthorizedEntity;
use pas9x\acme\dto\VerificationDataDns;
use pas9x\acme\dto\VerificationDataFile;
use pas9x\acme\exceptions\AcmeError;
use pas9x\acme\dto\VerificationData;
use pas9x\acme\Utils;

class Challenge extends AuthorizedEntity
{
    const VALIDATION_HTTP_01 = 'http-01';
    const VALIDATION_DNS_01 = 'dns-01';

    /** @deprecated https://community.letsencrypt.org/t/2018-01-11-update-regarding-acme-tls-sni-and-shared-hosting-infrastructure/50188 */
    const VALIDATION_TLS_SNI_01 = 'tls-sni-01';

    /** @deprecated https://community.letsencrypt.org/t/2018-01-11-update-regarding-acme-tls-sni-and-shared-hosting-infrastructure/50188 */
    const VALIDATION_TLS_SNI_02 = 'tls-sni-02';

    const STATUS_PENDING = 'pending';
    const STATUS_PROCESSING = 'processing'; // The ACME server attempts to validate the domain by making DNS or HTTP requests to the domain.
    const STATUS_VALID = 'valid';
    const STATUS_INVALID = 'invalid';

    public string $url;
    public string $type;
    public ?int $validated = null;
    public ?AcmeError $error = null;
    public ?string $token = null;

    protected bool $refreshed = false;

    /** @var VerificationData|null */
    protected $verificationData = null;

    protected function getRequiredAttributes(): array
    {
        return [
            'url',
            'type',
        ];
    }

    protected function setRawEntity(object $rawEntity): void
    {
        parent::setRawEntity($rawEntity);
        $this->url = $this->getAttribute('url');
        $this->type = $this->getAttribute('type');
        $this->validated = $this->optionalTime($this->getAttribute('validated'));
        $this->error = $this->optionalError($this->getAttribute('error'));
        $this->token = $this->getAttribute('token');
    }

    public function validate(): void
    {
        $this->authorized->executeAuthorizedRequest($this->getEntityUrl(), new \stdClass);
        $rawEntity = $this->internals->parseResponse(true);
        $this->setRawEntity($rawEntity);
    }

    public function getVerificationData(): VerificationData
    {
        if (empty($this->token)) {
            if ($this->refreshed) {
                throw new \RuntimeException('No token found after Challenge refreshed (1)');
            } else {
                $this->refresh();
                if (empty($this->token)) {
                    throw new \RuntimeException('No token found after Challenge refreshed (2)');
                }
            }
        }

        if ($this->verificationData === null) {
            $thumbprint_b64 = Utils::b64_urlencode(Utils::sha256($this->authorized->accountKey->getPublicKey()->getThumbprint()));
            $keyAuthorization = $this->token . '.' . $thumbprint_b64;
            $fileName = $this->getAttribute('token');
            $fileContent = $keyAuthorization;
            $txtRecord = Utils::b64_urlencode(Utils::sha256($keyAuthorization));
            $vFile = new VerificationDataFile($fileName, $fileContent);
            $vDns = new VerificationDataDNS($txtRecord);
            $this->verificationData = new VerificationData($vFile, $vDns);
        }
        return $this->verificationData;
    }

    public function refresh(): void
    {
        parent::refresh();
        $this->refreshed = true;
    }
}