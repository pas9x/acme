<?php

namespace pas9x\acme\crypto;

use pas9x\acme\dto\DNProp;
use pas9x\acme\Utils;
use phpseclib3\File\ASN1;
use phpseclib3\File\X509;
use ReflectionClass;

class DistinguishedName
{
    public static ?array $oid2name = null;
    public static ?array $name2oid = null;

    /**
     * @param DNProp[] $props
     */
    public function __construct(public array $props = [])
    {
    }

    /**
     * @param string $commonName
     * @param DNProp[] $props
     * @return self
     */
    public static function create(string $commonName, array $props = []): self
    {
        $props[] = new DNProp('2.5.4.3', $commonName, static::getNameByOid('2.5.4.3'));
        return new self($props);
    }

    public static function extractFromRdnSequence(array $rdnSequence): self
    {
        $props = [];
        foreach ($rdnSequence as $rdns) {
            if (Utils::isNumericArray($rdns)) {
                foreach ($rdns as $rdn) {
                    $prop = static::parseRdn($rdn);
                    if ($prop instanceof DNProp) {
                        $props[] = $prop;
                    }
                }
            } else {
                $prop = static::parseRdn($rdns);
                if ($prop instanceof DNProp) {
                    $props[] = $prop;
                }
            }
        }
        return new self($props);
    }

    protected static function parseRdn($rdn): ?DNProp
    {
        if (!is_array($rdn)) {
            return null;
        }
        if (empty($rdn['type']) || !is_string($rdn['type'])) {
            return null;
        }
        if (empty($rdn['value'])) {
            return null;
        }
        $oid = static::getOidByName($rdn['type']);
        if (empty($oid)) {
            return null;
        }
        $value = static::parseValue($rdn['value']);
        if ($value === null) {
            return null;
        }
        return new DNProp($oid, $value, $rdn['type']);
    }

    protected static function parseValue($value): ?string
    {
        if (is_scalar($value)) {
            return strval($value);
        }
        if (!is_array($value)) {
            return print_r($value, true);
        }
        $values = array_values($value);
        $count = count($values);
        if ($count < 1) {
            return null;
        }
        if ($count > 1) {
            return print_r($value, true);
        }
        $val = $values[0];
        return is_scalar($val) ? strval($val) : print_r($val, true);
    }

    protected static function initOids()
    {
        if (self::$oid2name === null || self::$name2oid === null) {
            self::$oid2name = self::loadOids();
            self::$name2oid = array_flip(self::$oid2name);
        }
    }

    public static function getNameByOid(string $oid): ?string
    {
        static::initOids();
        return self::$oid2name[$oid] ?? null;
    }

    public static function getOidByName(string $name): ?string
    {
        static::initOids();
        return self::$name2oid[$name] ?? null;
    }

    protected static function loadOids(): array
    {
        $default = [
            '2.5.4.3' => 'id-at-commonName',
        ];
        try {
            new X509; // Init oids. https://github.com/phpseclib/phpseclib/blob/6233a1e12584754e6b5daa69fe1289b47775c1b9/phpseclib/File/X509.php#L284
            $refClass = new ReflectionClass(ASN1::class);
            $refPropery = $refClass->getProperty('oids');
            $value = $refPropery->getValue();
            return is_array($value) ? $value : $default;
        } catch (\Throwable $e) {
            return $default;
        }
    }

    /**
     * @param string $oid
     * @return DNProp[]
     */
    public function getPropsByOid(string $oid): array
    {
        $result = [];
        foreach ($this->props as $prop) {
            if ($prop->oid === $oid) {
                $result[] = $prop;
            }
        }
        return $result;
    }

    public function getPropByOid(string $oid): ?string
    {
        $propName = static::getNameByOid($oid) ?? $oid;
        $props = $this->getPropsByOid($oid);
        $count = count($props);
        if ($count === 1) {
            return $props[0]->value;
        }
        if ($count < 1) {
            return null;
        }
        throw new \RuntimeException("This DistinguishedName has $count $propName properties. Don't know which one to return.");
    }

    public function getPropsByName(string $name): array
    {
        $result = [];
        foreach ($this->props as $prop) {
            $propName = static::getNameByOid($prop->oid);
            if ($propName === $name) {
                $result[] = $prop;
            }
        }
        return $result;
    }

    public function getPropByName(string $name): ?string
    {
        $props = $this->getPropsByName($name);
        $count = count($props);
        if ($count === 1) {
            return $props[0]->value;
        }
        if ($count < 1) {
            return null;
        }
        throw new \RuntimeException("This DistinguishedName has $count $name properties. Don't know which one to return.");
    }

    public function getCommonName(): ?string
    {
        return $this->getPropByOid('2.5.4.3');
    }

    public function writeToX509(X509 $x509): void
    {
        foreach ($this->props as $prop) {
            $name = static::getNameByOid($prop->oid);
            if (empty($name)) {
                throw new \RuntimeException("Cannot write DN property with oid={$prop->oid}. This oid is not supported by phpseclib.");
            }
            $ok = $x509->setDNProp($name, $prop->value);
            if ($ok !== true) {
                throw new \RuntimeException("Failed to write DN property with oid={$prop->oid}");
            }
        }
    }

    /**
     * @param string $nameOrOid
     * @param string $value
     * @return void
     *
     * Available propertiess:
     * id-qt-cps => 1.3.6.1.5.5.7.2.1,
     * id-qt-unotice => 1.3.6.1.5.5.7.2.2,
     * id-ad-ocsp => 1.3.6.1.5.5.7.48.1,
     * id-ad-caIssuers => 1.3.6.1.5.5.7.48.2,
     * id-ad-timeStamping => 1.3.6.1.5.5.7.48.3,
     * id-ad-caRepository => 1.3.6.1.5.5.7.48.5,
     * id-at-name => 2.5.4.41,
     * id-at-surname => 2.5.4.4,
     * id-at-givenName => 2.5.4.42,
     * id-at-initials => 2.5.4.43,
     * id-at-generationQualifier => 2.5.4.44,
     * id-at-commonName => 2.5.4.3,
     * id-at-localityName => 2.5.4.7,
     * id-at-stateOrProvinceName => 2.5.4.8,
     * id-at-organizationName => 2.5.4.10,
     * id-at-organizationalUnitName => 2.5.4.11,
     * id-at-title => 2.5.4.12,
     * id-at-description => 2.5.4.13,
     * id-at-dnQualifier => 2.5.4.46,
     * id-at-countryName => 2.5.4.6,
     * id-at-serialNumber => 2.5.4.5,
     * id-at-pseudonym => 2.5.4.65,
     * id-at-postalCode => 2.5.4.17,
     * id-at-streetAddress => 2.5.4.9,
     * id-at-uniqueIdentifier => 2.5.4.45,
     * id-at-role => 2.5.4.72,
     * id-at-postalAddress => 2.5.4.16,
     * jurisdictionOfIncorporationCountryName => 1.3.6.1.4.1.311.60.2.1.3,
     * jurisdictionOfIncorporationStateOrProvinceName => 1.3.6.1.4.1.311.60.2.1.2,
     * jurisdictionLocalityName => 1.3.6.1.4.1.311.60.2.1.1,
     * id-at-businessCategory => 2.5.4.15,
     * pkcs-9-at-emailAddress => 1.2.840.113549.1.9.1,
     * id-ce-authorityKeyIdentifier => 2.5.29.35,
     * id-ce-subjectKeyIdentifier => 2.5.29.14,
     * id-ce-keyUsage => 2.5.29.15,
     * id-ce-privateKeyUsagePeriod => 2.5.29.16,
     * id-ce-certificatePolicies => 2.5.29.32,
     * id-ce-policyMappings => 2.5.29.33,
     * id-ce-subjectAltName => 2.5.29.17,
     * id-ce-issuerAltName => 2.5.29.18,
     * id-ce-subjectDirectoryAttributes => 2.5.29.9,
     * id-ce-basicConstraints => 2.5.29.19,
     * id-ce-nameConstraints => 2.5.29.30,
     * id-ce-policyConstraints => 2.5.29.36,
     * id-ce-cRLDistributionPoints => 2.5.29.31,
     * id-ce-extKeyUsage => 2.5.29.37,
     * id-kp-serverAuth => 1.3.6.1.5.5.7.3.1,
     * id-kp-clientAuth => 1.3.6.1.5.5.7.3.2,
     * id-kp-codeSigning => 1.3.6.1.5.5.7.3.3,
     * id-kp-emailProtection => 1.3.6.1.5.5.7.3.4,
     * id-kp-timeStamping => 1.3.6.1.5.5.7.3.8,
     * id-kp-OCSPSigning => 1.3.6.1.5.5.7.3.9,
     * id-ce-inhibitAnyPolicy => 2.5.29.54,
     * id-ce-freshestCRL => 2.5.29.46,
     * id-pe-authorityInfoAccess => 1.3.6.1.5.5.7.1.1,
     * id-pe-subjectInfoAccess => 1.3.6.1.5.5.7.1.11,
     * id-ce-cRLNumber => 2.5.29.20,
     * id-ce-issuingDistributionPoint => 2.5.29.28,
     * id-ce-deltaCRLIndicator => 2.5.29.27,
     * id-ce-cRLReasons => 2.5.29.21,
     * id-ce-certificateIssuer => 2.5.29.29,
     * id-ce-holdInstructionCode => 2.5.29.23,
     * id-holdinstruction-none => 1.2.840.10040.2.1,
     * id-holdinstruction-callissuer => 1.2.840.10040.2.2,
     * id-holdinstruction-reject => 1.2.840.10040.2.3,
     * id-ce-invalidityDate => 2.5.29.24,
     * rsaEncryption => 1.2.840.113549.1.1.1,
     * md2WithRSAEncryption => 1.2.840.113549.1.1.2,
     * md5WithRSAEncryption => 1.2.840.113549.1.1.4,
     * sha1WithRSAEncryption => 1.2.840.113549.1.1.5,
     * sha224WithRSAEncryption => 1.2.840.113549.1.1.14,
     * sha256WithRSAEncryption => 1.2.840.113549.1.1.11,
     * sha384WithRSAEncryption => 1.2.840.113549.1.1.12,
     * sha512WithRSAEncryption => 1.2.840.113549.1.1.13,
     * id-ecPublicKey => 1.2.840.10045.2.1,
     * ecdsa-with-SHA1 => 1.2.840.10045.4.1,
     * ecdsa-with-SHA224 => 1.2.840.10045.4.3.1,
     * ecdsa-with-SHA256 => 1.2.840.10045.4.3.2,
     * ecdsa-with-SHA384 => 1.2.840.10045.4.3.3,
     * ecdsa-with-SHA512 => 1.2.840.10045.4.3.4,
     * id-dsa => 1.2.840.10040.4.1,
     * id-dsa-with-sha1 => 1.2.840.10040.4.3,
     * id-dsa-with-sha224 => 2.16.840.1.101.3.4.3.1,
     * id-dsa-with-sha256 => 2.16.840.1.101.3.4.3.2,
     * id-Ed25519 => 1.3.101.112,
     * id-Ed448 => 1.3.101.113,
     * id-RSASSA-PSS => 1.2.840.113549.1.1.10,
     * netscape => 2.16.840.1.113730,
     * netscape-cert-extension => 2.16.840.1.113730.1,
     * netscape-cert-type => 2.16.840.1.113730.1.1,
     * netscape-comment => 2.16.840.1.113730.1.13,
     * netscape-ca-policy-url => 2.16.840.1.113730.1.8,
     * id-pe-logotype => 1.3.6.1.5.5.7.1.12,
     * entrustVersInfo => 1.2.840.113533.7.65.0,
     * verisignPrivate => 2.16.840.1.113733.1.6.9,
     * pkcs-9-at-unstructuredName => 1.2.840.113549.1.9.2, // PKCS #9 unstructured name
     * pkcs-9-at-challengePassword => 1.2.840.113549.1.9.7, // Challenge password for certificate revocations
     * pkcs-9-at-extensionRequest => 1.2.840.113549.1.9.14 // Certificate extension request
     */
    public function setProperty(string $nameOrOid, string $value, bool $replace = true): self
    {
        $prop = static::resolve($nameOrOid);
        if (empty($prop)) {
            throw new \ValueError('Unsupported property: ' . $nameOrOid);
        }
        if ($replace) {
            $this->deleteProperty($prop['oid']);
        }
        $this->props[] = new DNProp($prop['oid'], $value, $prop['name']);
        return $this;
    }

    public function deleteProperty(string $nameOrOid): bool
    {
        $prop = static::resolve($nameOrOid, false);
        if (empty($prop)) {
            return false;
        }

        $deleted = false;
        foreach ($this->props as $index => $item) {
            if ($prop['oid'] === $item->oid) {
                unset($this->props[$index]);
                $deleted = true;
            }
        }

        return $deleted;
    }

    protected static function resolve(string $nameOrOid, bool $required = true): ?array
    {
        if (preg_match('/^[0-9\.]+$/', $nameOrOid)) {
            $oid = $nameOrOid;
            $name = static::getNameByOid($oid);
        } else {
            $name = $nameOrOid;
            $oid = static::getOidByName($name);
        }
        if (empty($oid) || empty($name)) {
            if ($required) {
                throw new \ValueError('Unsupported property: ' . $nameOrOid);
            } else {
                return null;
            }
        }
        return compact('oid', 'name');
    }
}