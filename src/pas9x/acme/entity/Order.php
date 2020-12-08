<?php

namespace pas9x\acme\entity;

use LogicException;
use pas9x\acme\dto\Certificate;
use pas9x\acme\dto\OrderIdentifier;
use pas9x\acme\contracts\CSR;
use pas9x\acme\exceptions\UnexpectedResponse;
use pas9x\acme\implementations\crypto\RSACSR;
use pas9x\acme\dto\DistinguishedName;
use pas9x\acme\Utils;

class Order extends Entity
{
    protected $account;

    /** @var OrderIdentifier[] */
    protected $identifiers = [];

    /** @var int|null */
    protected $notBefore = null;

    /** @var int|null */
    protected $notAfter = null;

    /** @var array $authorizations */
    protected $authorizations = null;

    /** @var string|null $primaryDomain */
    protected $primaryDomain = null;

    public function __construct(string $entityUrl, array $rawEntity, Account $account)
    {
        parent::__construct($entityUrl, $rawEntity);
        $this->account = $account;
        $this->refresh($rawEntity);
    }

    /** @return OrderIdentifier[] */
    public function identifiers(): array
    {
        return $this->identifiers;
    }

    public function notBefore(): ?int
    {
        return $this->notBefore;
    }

    public function notAfter(): ?int
    {
        return $this->notAfter;
    }

    public function finalize(): string
    {
        return $this->getAttribute('finalize');
    }

    public function certificate(): ?string
    {
        return $this->getAttribute('certificate', null);
    }

    public function primaryDomain(string $newPrimaryDomain = null): string
    {
        if ($newPrimaryDomain === null) {
            $this->primaryDomain = $newPrimaryDomain;
        }
        if ($this->primaryDomain === null) {
            return $this->identifiers()[0]->value();
        } else {
            return $this->primaryDomain;
        }
    }

    public function registerCertificate(CSR $csr = null)
    {
        if ($csr === null) {
            $dn = new DistinguishedName($this->primaryDomain());
            $sanDomains = [];
            foreach ($this->identifiers() as $identifier) {
                if ($identifier->value() !== $dn->commonName()) {
                    $sanDomains[] = $identifier->value();
                }
            }
            $csr = RSACSR::generate($dn, $sanDomains);
        }

        $payload = [
            'csr' => Utils::b64_urlencode(Utils::pemToDer($csr->getCsrPem())),
        ];
        $this->account->internals()->joseRequest($this->finalize(), $payload);
        $rawOrder = $this->account->acme()->internals()->parseResponse(true);
        $this->refresh($rawOrder);
    }

    public function downloadCertificate(): Certificate
    {
        $url = $this->certificate();
        if ($url === null) {
            if ($this->status() === 'valid') {
                throw new LogicException('Order status is `valid`, but it has no link to download certificate. You probably need to call registerCertificate() first.');
            } else {
                throw new LogicException("Order status is `" . $this->status() . "`. You cannot getCertificate until order status is not `valid`.");
            }
        }
        $this->account->internals()->joseRequest($url);
        $this->account->acme()->internals()->parseResponse(false);
        $responseBody = $this->account->acme()->httpClient()->lastResponse()->body();
        preg_match_all('/\-+[ \t]*BEGIN CERTIFICATE[ \t]*\-+\s+.+\s+\-+[ \t]*END CERTIFICATE[ \t]*\-+(?:\s|$)/siU', $responseBody, $matches);
        if (!isset($matches[0][0])) {
            throw new UnexpectedResponse('No certificates returned', $responseBody);
        }
        $caChain = $matches[0];
        $certificate = $caChain[0];
        array_shift($caChain);
        $result = new Certificate($certificate, $caChain);
        return $result;
    }

    /**
     * @param bool $useCache
     * @return Authorization[]
     */
    public function authorizations(bool $useCache = true): array
    {
        if ($this->authorizations === null || !$useCache) {
            $authorizations = [];
            foreach ($this->getAttribute('authorizations') as $authorizationUrl) {
                $authorizations[] = $this->account->getAuthorization($authorizationUrl);
            }
            $this->authorizations = $authorizations;
        }
        return $this->authorizations;
    }

    public function refresh(array $rawEntity = null)
    {
        if ($rawEntity === null) {
            $rawEntity = $this->account->internals()->getRawEntity($this->url());
        }

        $identifiers = [];
        $notBefore = null;
        $notAfter = null;

        foreach ($rawEntity['identifiers'] as $identifier) {
            $identifiers[] = new OrderIdentifier($identifier['type'], $identifier['value']);
        }
        if (!empty($rawEntity['notBefore'])) {
            $notBefore = strtotime($rawEntity['notBefore']);
            if (!is_int($notBefore)) $notBefore = null;
        }
        if (!empty($rawEntity['notAfter'])) {
            $notAfter = strtotime($rawEntity['notAfter']);
            if (!is_int($notAfter)) $notAfter = null;
        }

        if ($this->construct) {
            $this->construct = false;
        } else {
            $this->setRawEntity($rawEntity);
        }

        $this->identifiers = $identifiers;
        $this->notBefore = $notBefore;
        $this->notAfter = $notAfter;
        $this->authorizations = null;
    }

    /** @return string[] */
    protected function requiredAttributes(): array
    {
        return [
            'identifiers',
            'authorizations',
            'finalize',
        ];
    }
}