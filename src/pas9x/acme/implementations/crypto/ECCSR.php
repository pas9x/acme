<?php

namespace pas9x\acme\implementations\crypto;

use Exception;
use pas9x\acme\contracts\CSR;
use pas9x\acme\contracts\PrivateKey;
use pas9x\acme\dto\DistinguishedName;
use pas9x\acme\Utils;

class ECCSR implements CSR
{
    protected $csrPem;
    protected $privateKey;

    public function __construct(string $csrPem, string $privateKeyPem)
    {
        $this->csrPem = $csrPem;
        $this->privateKey = new ECPrivateKey($privateKeyPem);
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
                'private_key_type' => OPENSSL_KEYTYPE_EC,
                'curve_name' => 'prime256v1',
            ];
            $privateKey = openssl_pkey_new($args);
            openssl_pkey_export($privateKey, $privateKeyPem);
        } else {
            $privateKey = openssl_pkey_get_private($privateKeyPem);
            $details = openssl_pkey_get_details($privateKey);
            if ($details['type'] !== OPENSSL_KEYTYPE_EC) {
                throw new Exception('This is not an EC key');
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