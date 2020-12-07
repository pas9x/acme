<?php

namespace pas9x\acme\implementations\crypto;

use LogicException;
use Exception;
use phpseclib\Crypt\RSA;
use phpseclib\File\X509;
use pas9x\acme\contracts\CSR;
use pas9x\acme\contracts\PrivateKey;
use pas9x\acme\dto\DistinguishedName;
use pas9x\acme\Utils;

class RSACSR implements CSR
{
    protected $csrPem;
    protected $privateKey;

    public function __construct(string $csrPem, string $privateKeyPem)
    {
        $this->csrPem = $csrPem;
        $this->privateKey = new RSAPrivateKey($privateKeyPem);
    }

    public function getCsrPem(): string
    {
        return $this->csrPem;
    }

    public function getPrivateKey(): PrivateKey
    {
        return $this->privateKey;
    }

    public static function generate(
        DistinguishedName $dn,
        array $sanDomains = [],
        array $sanIPs = [],
        string $privateKeyPem = null,
        string $tmpDir = null,
        string $engine = null
    ): self
    {
        if ($engine === null) {
            if (Utils::engineAvailable(Utils::ENGINE_PHPSECLIB)) {
                return static::generateByPhpseclib($dn, $sanDomains, $sanIPs, $privateKeyPem);
            }
            if (Utils::engineAvailable(Utils::ENGINE_OPENSSL)) {
                return static::generateByOpenssl($dn, $sanDomains, $sanIPs, $privateKeyPem, $tmpDir);
            }
            throw new Exception('No engine to generate CSR');
        } else {
            if (!Utils::engineAvailable($engine)) {
                throw new Exception($engine . ' engine is not available');
            }
            if ($engine === Utils::ENGINE_PHPSECLIB) {
                return static::generateByPhpseclib($dn, $sanDomains, $sanIPs, $privateKeyPem);
            }
            if ($engine === Utils::ENGINE_OPENSSL) {
                return static::generateByOpenssl($dn, $sanDomains, $sanIPs, $privateKeyPem, $tmpDir);
            }
            throw new LogicException;
        }
    }

    protected static function generateByPhpseclib(
        DistinguishedName $dn,
        array $sanDomains = [],
        array $sanIPs = [],
        string $privateKeyPem = null
    ): self
    {
        if ($privateKeyPem === null) {
            $generator = new RSAPrivateKeyGenerator(4096, Utils::ENGINE_PHPSECLIB);
            $key = $generator->generatePrivateKey();
            $privateKeyPem = $key->getPrivateKeyPem();
        }
        $privateKey = new RSA;
        $ok = $privateKey->loadKey($privateKeyPem);
        if ($ok !== true) {
            throw new Exception('RSA->loadKey() failed');
        }

        $x509 = new X509;
        $x509->setPrivateKey($privateKey);
        $x509->setDNProp('commonname', $dn->commonName());
        $x509->setDNProp('organizationname', $dn->organizationName());
        $x509->setDNProp('organizationalunitname', $dn->organizationalUnit());
        $x509->setDNProp('localityname', $dn->locality());
        $x509->setDNProp('state', $dn->state());
        $x509->setDNProp('countryname', $dn->country());
        $x509->setDNProp('emailaddress', $dn->emailAddress());

        $san = [];
        if (!empty($sanDomains)) {
            foreach ($sanDomains as $domain) {
                $san[] = ['dNSName' => $domain];
            }
        }
        if (!empty($sanIPs)) {
            foreach ($sanIPs as $ip) {
                $san[] = ['iPAddress' => $ip];
            }
        }
        if (!empty($san)) {
            $x509->currentCert = $x509->signCSR();
            $x509->setExtension('id-ce-subjectAltName', $san);
        }

        $csrStruct = $x509->signCSR();
        if (empty($csrStruct)) {
            throw new Exception('CSR generation failed (1)');
        }

        $csrPem = $x509->saveCSR($csrStruct, X509::FORMAT_PEM);
        return new self($csrPem, $privateKeyPem);
    }

    protected static function generateByOpenssl(
        DistinguishedName $dn,
        array $sanDomains = [],
        array $sanIPs = [],
        string $privateKeyPem = null,
        string $tmpDir = null
    ): self
    {
        $options = [];

        if (!empty($sanDomains) || !empty($sanIPs)) {
            if ($tmpDir === null) {
                $tmpDir = Utils::getTmpDir();
            }
            $config  = "[req]\n";
            $config .= "distinguished_name = req_distinguished_name\n";
            $config .= "req_extensions = v3_req\n";
            $config .= "[req_distinguished_name]\n";
            $config .= "[v3_req]\n";
            $config .= "subjectAltName = @san\n";
            $config .= "[san]\n";
            foreach ($sanDomains as $index => $domain) {
                $config .= "DNS.$index=$domain\n";
            }
            foreach ($sanIPs as $index => $ip) {
                $config .= "IP.$index=$ip\n";
            }
            $tmpFile = $tmpDir . '/openssl_' . strtoupper(Utils::randomString(16)) . '.cnf';
            Utils::filePutContents($tmpFile, $config);

            $options['config'] = $tmpFile;
        }

        if ($privateKeyPem === null) {
            $args = [
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
                'private_key_bits' => 4096,
            ];
            $privateKey = openssl_pkey_new($args);
            openssl_pkey_export($privateKey, $privateKeyPem);
        } else {
            $privateKey = openssl_pkey_get_private($privateKeyPem);
            $details = openssl_pkey_get_details($privateKey);
            if ($details['type'] !== OPENSSL_KEYTYPE_RSA) {
                throw new Exception('This is not an RSA key');
            }
        }

        $dnArr = [
            'commonName' => $dn->commonName(),
            'organizationName' => $dn->organizationName(),
            'organizationalUnitName' => $dn->organizationalUnit(),
            'localityName' => $dn->locality(),
            'stateOrProvinceName' => $dn->state(),
            'countryName' => $dn->country(),
            'emailAddress' => $dn->emailAddress(),
        ];
        $csr = openssl_csr_new($dnArr, $privateKey, $options);
        if (isset($options['config'])) {
            @unlink($options['config']);
        }
        if (empty($csr)) {
            throw new Exception('openssl_csr_new() failed');
        }
        $ok = openssl_csr_export($csr, $csrPem, true);
        if ($ok !== true || !is_string($csrPem) || $csrPem === '') {
            throw new Exception('openssl_csr_export() failed');
        }

        return new self($csrPem, $privateKeyPem);
    }
}