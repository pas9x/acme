<?php

namespace pas9x\acme\entity;

use pas9x\acme\AuthorizedEntity;
use pas9x\acme\crypto\DistinguishedName;
use pas9x\acme\crypto\Certificate;
use pas9x\acme\crypto\CSR;
use pas9x\acme\dto\OrderIdentifier;
use pas9x\acme\dto\RegisteredCertificate;
use pas9x\acme\exceptions\AcmeError;
use pas9x\acme\exceptions\UnexpectedResponse;
use pas9x\acme\Utils;

class Order extends AuthorizedEntity
{
    const STATUS_PENDING = 'pending'; // New orders are created in the "pending" state
    const STATUS_READY = 'ready'; // All of the authorizations are in the "valid" state. Ready to registerCertificate().
    const STATUS_PROCESSING = 'processing'; // The client sent a request to the order's "finalize" URL and the CA begins the issuance process for the certificate. Wait for STATUS_VALID status.
    const STATUS_VALID = 'valid'; // Certificate is issued. Ready to downloadCertificate()
    const STATUS_INVALID = 'invalid';

    /** @var OrderIdentifier[] */
    public array $identifiers;

    /** @var string[] $authorizations */
    public array $authorizations;

    public ?int $expires;
    public ?int $notBefore = null;
    public ?int $notAfter = null;
    public string $finalize;
    public ?string $certificate = null;
    public ?AcmeError $error = null;

    /** @var Authorization[] $authorizationEntities */
    protected ?array $authorizationEntities = null;

    protected function getRequiredAttributes(): array
    {
        return [
            'identifiers',
            'authorizations',
            'finalize',
        ];
    }

    protected function setRawEntity(object $rawEntity): void
    {
        parent::setRawEntity($rawEntity);

        $this->expires = $this->optionalTime($this->getAttribute('expires'));

        $identifiers = $this->getAttribute('identifiers');
        $this->identifiers = [];
        foreach ($identifiers as $identifier) {
            $this->identifiers[] = new OrderIdentifier($identifier->type, $identifier->value);
        }

        $this->notBefore = $this->optionalTime($this->getAttribute('notBefore'));
        $this->notAfter = $this->optionalTime($this->getAttribute('notAfter'));
        $this->authorizations = $this->getAttribute('authorizations');
        $this->finalize = $this->getAttribute('finalize');
        $this->certificate = $this->getAttribute('certificate');
        $this->error = $this->optionalError($this->getAttribute('error'));
    }

    public function getAuthorization(string $entityUrl): Authorization
    {
        return $this->authorized->getAuthorization($entityUrl);
    }

    /**
     * @param bool $useCache
     * @return Authorization[]
     */
    public function getAuthorizations(bool $useCache = true): array
    {
        if ($this->authorizationEntities === null || $useCache) {
            $entities = [];
            foreach ($this->authorizations as $entityUrl) {
                $entities[] = $this->getAuthorization($entityUrl);
            }
            $this->authorizationEntities = $entities;
        }
        return $this->authorizationEntities;
    }

    public function registerCertificate(?string $primaryDomain = null, ?CSR $csr = null): CSR
    {
        if ($this->status !== self::STATUS_READY) {
            throw new \LogicException('Order status is not `' . self::STATUS_READY . "` yet. Actual order status is `{$this->status}`. Can't register certificate.");
        }

        if ($csr === null) {
            if (empty($primaryDomain)) {
                $primaryDomain = $this->detectPrimaryDomain();
            } else {
                $this->validatePrimaryDomain($primaryDomain);
            }

            $dn = DistinguishedName::create($primaryDomain);
            $sanDomains = [];
            foreach ($this->identifiers as $identifier) {
                if ($identifier->value !== $dn->getCommonName()) {
                    $sanDomains[] = $identifier->value;
                }
            }
            $csr = CSR::generate($dn, $sanDomains);
        }

        $payload = new \stdClass;
        $payload->csr = Utils::b64_urlencode(Utils::pemToDer($csr->csrPem));
        file_put_contents('/tmp/csr.txt', $payload->csr);

        $this->authorized->executeAuthorizedRequest($this->finalize, $payload);
        $rawOrder = $this->internals->parseResponse(true);
        $this->setRawEntity($rawOrder);

        return $csr;
    }

    protected function detectPrimaryDomain(): string
    {
        foreach ($this->identifiers as $identifier) {
            if ($identifier->type == OrderIdentifier::TYPE_DNS) {
                return $identifier->value;
            }
        }
        throw new \LogicException('Failed to determine primary domain');
    }

    protected function validatePrimaryDomain(string $domain)
    {
        foreach ($this->identifiers as $identifier) {
            if ($identifier->type == OrderIdentifier::TYPE_DNS && $identifier->value === $domain) {
                return;
            }
        }
        throw new \InvalidArgumentException("This order have no domain `$domain`");
    }

    public function downloadCertificate(): RegisteredCertificate
    {
        if ($this->status !== self::STATUS_VALID) {
            throw new \LogicException('Order status is not `' . self::STATUS_VALID . "` yet. Actual order status is `{$this->status}`. Can't download certificate.");
        }

        $url = $this->certificate;
        if (empty($url)) {
            throw new \LogicException("Order status is `{$this->status}`, but there is no certificate download link. This shouldn't have happened. The ACME server may have responded incorrectly.");
        }

        $this->authorized->executeAuthorizedRequest($url);
        $this->internals->parseResponse(false);
        $responseBody = $this->internals->lastResponse->body;
        preg_match_all('/\-+[ \t]*BEGIN CERTIFICATE[ \t]*\-+\s+.+\s+\-+[ \t]*END CERTIFICATE[ \t]*\-+(?:\s|$)/siU', $responseBody, $matches);
        if (!isset($matches[0][0])) {
            throw new UnexpectedResponse('No certificates returned', $responseBody);
        }

        // TODO: use subject key identifiers and isCA to determine $certificate correctly
        $caChainPems = $matches[0];
        $certificatePem = array_shift($caChainPems);
        $certificate = new Certificate($certificatePem);
        $caChain = RegisteredCertificate::wrapChain($caChainPems);
        $result = new RegisteredCertificate($certificate, $caChain);

        return $result;
    }
}