<?php

namespace pas9x\acme\crypto;

use pas9x\acme\crypto\helpers\X509ExtensionsParser;
use pas9x\acme\dto\SanName;
use phpseclib3\File\X509;

class Certificate
{
    public readonly string $suggestedCertificateName;
    public readonly DistinguishedName $distinguishedName;
    /** @var SanName[] $sanNames */
    public readonly array $sanNames;
    public readonly int $notBefore;
    public readonly int $notAfter;
    public readonly string $subjectKeyIdentifier;
    public readonly string $authorityKeyIdentifier;
    public readonly bool $isCA;
    public readonly string $pem;

    public readonly X509 $phpseclibCertificate;
    public readonly array $details;
    protected ?X509ExtensionsParser $extensions = null;
    protected ?PublicKey $publicKey = null;

    public function __construct(string|X509 $certificate)
    {
        if (is_string($certificate)) {
            $phpseclibCert = new X509;
            $details = $phpseclibCert->loadX509($certificate);
            if (empty($details) || !is_array($details)) {
                throw new \RuntimeException('Failed to parse string as X509 certificate');
            }
        } elseif ($certificate instanceof X509) {
            $phpseclibCert = $certificate;
        } else {
            throw new \LogicException;
        }

        $details = $phpseclibCert->getCurrentCert();
        if (empty($details['tbsCertificate']) || !is_array($details['tbsCertificate'])) {
            throw new \RuntimeException('Failed to parse X509 file: not an certificate');
        }
        $this->phpseclibCertificate = $phpseclibCert;
        $subject = $details['tbsCertificate']['subject'] ?? null;
        if (!is_array($subject)) {
            throw new \RuntimeException('Failed to parse X509 certificate: no subject');
        }

        $this->details = $details;
        $this->extensions = new X509ExtensionsParser($details['tbsCertificate']['extensions'] ?? []);
        $this->distinguishedName = DistinguishedName::extractFromRdnSequence($subject['rdnSequence'] ?? []);
        $this->notBefore = $this->timestamp($details['tbsCertificate']['validity']['notBefore']['utcTime'] ?? null);
        $this->notAfter = $this->timestamp($details['tbsCertificate']['validity']['notAfter']['utcTime'] ?? null);
        $this->sanNames = $this->parseSansNames();
        $this->subjectKeyIdentifier = $this->parseSubjectKeyIdentifier();
        $this->authorityKeyIdentifier = $this->parseAuthorityKeyIdentifier();
        $this->isCA = $this->parseIsCA();
        $this->pem = $phpseclibCert->saveX509($details, X509::FORMAT_PEM);
        $this->suggestedCertificateName = $this->suggestCertificateName();
        $this->extensions = null;
    }

    public function getPublicKey(): PublicKey
    {
        if ($this->publicKey === null) {
            $this->publicKey = new PublicKey($this->phpseclibCertificate->getPublicKey());
        }
        return $this->publicKey;
    }

    protected function timestamp($strtime): int
    {
        if (empty($strtime)) {
            return 0;
        }
        if (!is_string($strtime)) {
            return 0;
        }
        $ts = strtotime($strtime);
        return is_int($ts) ? $ts : 0;
    }

    protected function parseSansNames(): array
    {
        $values = $this->extensions->getExtensions('id-ce-subjectAltName');
        $sanNames = [];
        foreach ($values as $value) {
            if (!is_array($value)) {
                continue;
            }
            if (isset($value['dNSName'])) {
                $sanNames[] = new SanName(SanName::TYPE_DNS, $value['dNSName']);
            } elseif (isset($value['iPAddress'])) {
                $sanNames[] = new SanName(SanName::TYPE_IP, $value['iPAddress']);
            }
        }
        return $sanNames;
    }

    protected function parseSubjectKeyIdentifier(): string
    {
        $value = $this->extensions->getExtension('id-ce-subjectKeyIdentifier');
        if (empty($value)) {
            throw new \RuntimeException('Certificate subject key identifier not found');
        }
        if (!is_string($value)) {
            throw new \RuntimeException('Failed to parse subject key identifier');
        }
        return $this->formatIdentifier($value);
    }

    protected function parseAuthorityKeyIdentifier(): ?string
    {
        $value = $this->extensions->getExtension('id-ce-authorityKeyIdentifier');
        if (empty($value)) {
            return null;
        }
        if (!isset($value['keyIdentifier']) || !is_string($value['keyIdentifier'])) {
            throw new \RuntimeException('Failed to parse authority key identifier');
        }
        return $this->formatIdentifier($value['keyIdentifier']);
    }

    protected function formatIdentifier(string $raw): string
    {
        $hex = strtoupper(bin2hex($raw));
        return trim(chunk_split($hex, 2, ':'), ':');
    }

    protected function parseIsCA(): bool
    {
        $values = $this->extensions->getExtensions('id-ce-basicConstraints');
        foreach ($values as $value) {
            if (!empty($value['cA'])) {
                return true;
            }
        }
        return false;
    }

    protected function suggestCertificateName(): string
    {
        $cn = $this->distinguishedName->getCommonName();
        if (!empty($cn)) {
            return $cn;
        }

        foreach ($this->sanNames as $sanName) {
            if ($sanName->type === SanName::TYPE_DNS) {
                return $sanName->value;
            }
        }

        return str_replace(':', '', $this->subjectKeyIdentifier);
    }
}