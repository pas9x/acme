<?php

namespace pas9x\acme\exceptions;

class AcmeError extends \RuntimeException
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

    /** @var AcmeError[] $subproblems */
    public $subproblems = [];

    /**
     * @param string $type
     * @param string $detail
     * @param int $httpCode
     * @param array $rawError
     */
    public function __construct(string $type, ?string $detail, ?int $httpCode, array $rawError)
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
        if ($httpCode !== null) {
            $message .= ", httpCode=$httpCode";
            $pure .= ", httpCode=$httpCode";
        }

        if (isset($rawError['subproblems']) && is_array($rawError['subproblems'])) {
            foreach ($rawError['subproblems'] as $subproblem) {
                if (isset($subproblem['type'])) {
                    $this->subproblems[] = new self($subproblem['type'], $subproblem['detail'] ?? null, $httpCode, $subproblem);
                }
            }
            $count = count($rawError['subproblems']);
            $message .= ", $count subproblems";
            $pure .= ", $count subproblems";
        }

        $this->rawError = $rawError;
        $this->pureMessage = $pure;
        parent::__construct($message);
    }
}