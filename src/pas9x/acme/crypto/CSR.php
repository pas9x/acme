<?php

namespace pas9x\acme\crypto;

use pas9x\acme\dto\SanName;
use pas9x\acme\enums\ECKeyCurve;
use phpseclib3\File\X509;

class CSR
{
    public readonly DistinguishedName $distinguishedName;
    /** @var SanName[] $sanNames */
    public readonly array $sanNames;

    public readonly X509 $phpseclibCsr;
    public readonly array $details;

    public function __construct(
        public readonly string $csrPem,
        public readonly ?PrivateKey $privateKey)
    {
        $phpseclibCsr = new X509;
        $details = $phpseclibCsr->loadCSR($this->csrPem);
        if (empty($details) || !is_array($details)) {
            throw new \ValueError('Failed to parse CSR');
        }

        $details = $phpseclibCsr->getCurrentCert();
        if (empty($details['certificationRequestInfo'])) {
            throw new \ValueError('Failed to parse X509 file: not an CSR request');
        }

        if (empty($details['certificationRequestInfo']['subject'])) {
            throw new \RuntimeException('Failed to parse CSR request: no subject');
        }

        $this->details = $details;
        $this->phpseclibCsr = $phpseclibCsr;
        $this->distinguishedName = DistinguishedName::extractFromRdnSequence($details['certificationRequestInfo']['subject']['rdnSequence'] ?? []);
        $this->sanNames = $this->parseSanNames();
    }

    /**
     * @param string|DistinguishedName $distinguishedName Domain name (string) or full DistinguishedName
     * @param string[] $sanDomains Additional domains
     * @param string[] $sanIPs
     * @param PrivateKey|null $privateKey
     * @return self
     */
    public static function generate(
        string|DistinguishedName $distinguishedName,
        array $sanDomains = [],
        array $sanIPs = [],
        ?PrivateKey $privateKey = null,
    ): self
    {
        if (is_string($distinguishedName)) {
            $dn = DistinguishedName::create($distinguishedName);
        } elseif ($distinguishedName instanceof DistinguishedName) {
            $dn = $distinguishedName;
        } else {
            throw new \LogicException;
        }

        if ($privateKey === null) {
            $privateKey = PrivateKeyEC::generate(ECKeyCurve::P256);
        }

        $x509 = new X509;
        $x509->setPrivateKey($privateKey->phpseclibPrivateKey);

        $dn->writeToX509($x509);

        $san = [];
        foreach ($sanDomains as $domain) {
            $san[] = ['dNSName' => $domain];
        }
        foreach ($sanIPs as $ip) {
            $san[] = ['iPAddress' => $ip];
        }
        $x509->loadCSR($x509->saveCSR($x509->signCSR())); // Yes, it is recommended by phpseclib author. Without this duct tape setExtension() call will not work. See https://phpseclib.com/docs/csr
        $x509->setExtension('id-ce-subjectAltName', $san);

        $details = $x509->signCSR();
        if (empty($details) || !is_array($details)) {
            throw new \RuntimeException('Failed to sign CSR');
        }

        $csrPem = $x509->saveCSR($details);
        if (empty($csrPem) || !is_string($csrPem)) {
            throw new \RuntimeException('Failed to export CSR PEM');
        }

        return new self($csrPem, $privateKey);
    }

    /**
     * @return SanName[]
     */
    protected function parseSanNames(): array
    {
        $attrs = $this->details['certificationRequestInfo']['attributes'] ?? null;
        if (empty($attrs)) {
            return [];
        }

        $sanNames = [];

        foreach ($attrs as $attr) {
            $attrType = $attr['type'] ?? null;
            if ($attrType !== 'pkcs-9-at-extensionRequest') {
                continue;
            }
            if (empty($attr['value']) || !is_array($attr['value'])) {
                continue;
            }
            foreach ($attr['value'] ?? [] as $values) {
                if (!is_array($values)) {
                    continue;
                }
                foreach ($values as $value) {
                    $extnId = $value['extnId'] ?? null;
                    if ($extnId !== 'id-ce-subjectAltName') {
                        continue;
                    }
                    if (empty($value['extnValue']) || !is_array($value['extnValue'])) {
                        continue;
                    }
                    foreach ($value['extnValue'] as $rawSanName) {
                        if (!empty($rawSanName['dNSName'])) {
                            $sanNames[] = new SanName(SanName::TYPE_DNS, $rawSanName['dNSName']);
                        } elseif (!empty($rawSanName['iPAddress'])) {
                            $sanNames[] = new SanName(SanName::TYPE_IP, $rawSanName['iPAddress']);
                        }
                    }
                }
            }
        }

        return $sanNames;
    }

    /**
     * @return string[]
     */
    public function getSanDomains(): array
    {
        $domains = [];
        foreach ($this->sanNames as $sanName) {
            if ($sanName->type === SanName::TYPE_DNS) {
                $domains[] = $sanName->value;
            }
        }
        return $domains;
    }

    /**
     * @return string[]
     */
    public function getSanIPs(): array
    {
        $domains = [];
        foreach ($this->sanNames as $sanName) {
            if ($sanName->type === SanName::TYPE_IP) {
                $domains[] = $sanName->value;
            }
        }
        return $domains;
    }
}