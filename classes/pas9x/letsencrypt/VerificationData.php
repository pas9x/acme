<?php

namespace pas9x\letsencrypt;

class VerificationData
{
    /** @var string|null $fileUri */
    public $fileUri = null;

    /** @var string|null $fileContent */
    public $fileContent = null;

    /** @var string|null $txtRecord */
    public $txtRecord = null;
}