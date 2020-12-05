<?php

namespace pas9x\acme\dto;

class VerificationData
{
    protected $fileUri = null;
    protected $fileContent = null;
    protected $txtRecord = null;

    public function __construct(string $fileUri, string $fileContent, string $txtRecord)
    {
        $this->fileUri = $fileUri;
        $this->fileContent = $fileContent;
        $this->txtRecord = $txtRecord;
    }

    public function fileUri(): string
    {
        return $this->fileUri;
    }

    public function fileContent(): string
    {
        return $this->fileContent;
    }

    public function txtRecord(): string
    {
        return $this->txtRecord;
    }
}
