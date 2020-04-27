<?php

use \pas9x\letsencrypt\DomainVerifierHttp;
use \pas9x\letsencrypt\DomainVerifierDns;

class ArrayPathNotFound extends Exception
{
    public $path;

    /** @param string $path */
    public function __construct($message, $path)
    {
        $this->path = $path;
        parent::__construct($message);
    }
}

class HttpVerifier extends DomainVerifierHttp
{
    public $domainName;
    public $documentRoot;
    public $verificationFile;

    public function __construct($domainName, $documentRoot)
    {
        $this->domainName = $domainName;
        $this->documentRoot = $documentRoot;
    }

    /** @inheritdoc */
    public function domainName()
    {
        return $this->domainName;
    }

    public function cleanup()
    {
        if (!empty($this->verificationFile) && file_exists($this->verificationFile)) {
            unlink($this->verificationFile);
        }
    }

    public function putFile($uri, $content)
    {
        $this->verificationFile = $this->documentRoot . '/' . $uri;
        $dir = dirname($this->verificationFile);
        if (!is_dir($dir)) {
            if (!mkdir($dir, 0755, true)) {
                throw new Exception('Failed to create directory ' . $dir);
            }
        }
        $bytesWritten = file_put_contents($this->verificationFile, $content);
        if ($bytesWritten !== strlen($content)) {
            throw new Exception('Failed to write file ' . $this->verificationFile);
        }
    }
}

class DnsVerifier extends DomainVerifierDns
{
    public $domainName;
    public $recordName;

    public function __construct($domainName)
    {
        $this->domainName = $domainName;
        $this->recordName = '_acme-challenge.' . $domainName;
    }

    /** @inheritdoc */
    public function domainName()
    {
        return $this->domainName;
    }

    public function cleanup()
    {
        stdout("Now you can remove {$this->recordName} record\n");
    }

    public function setTxtRecord($value)
    {
        stdout("Set following TXT record for domain {$this->recordName}:\n");
        stdout("$value\n");
        stdout("Press [enter] to continue");
        fgets(STDIN);
    }
}