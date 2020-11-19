<?php

namespace pas9x\letsencrypt;

class AcmeError extends \Exception
{
    /** @var string $type */
    public $type;

    /** @var int $detail */
    public $detail;

    /** @var int $httpCode */
    public $httpCode;

    /** @var array $rawError */
    public $rawError;

    /** @var string $pureMessage */
    public $pureMessage;

    /**
     * @param string $type
     * @param string $detail
     * @param int $httpCode
     * @param array $rawError
     */
    public function __construct($type, $detail, $httpCode, array $rawError)
    {
        $this->type = $type;
        $this->detail = $detail;
        $this->httpCode = $httpCode;
        $message = 'ACME error';
        if (empty($detail)) {
            $message .= ", type=$type";
            $pure = "type=$type";
        } else {
            $message .= ": $detail";
            $pure = $detail;
        }
        $message .= ", http_code=$httpCode";
        $pure .= ", http_code=$httpCode";
        $this->rawError = $rawError;
        $this->pureMessage = $pure;
        parent::__construct($message);
    }
}