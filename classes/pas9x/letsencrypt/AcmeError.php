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
        if (!empty($detail)) {
            $message .= ": $detail";
        } else {
            $message .= ", type=$type";
        }
        $message .= ", http_code=$httpCode";
        $this->rawError = $rawError;
        parent::__construct($message);
    }
}