<?php

namespace pas9x\acme\exceptions;

class AcmeError extends \RuntimeException
{
    /** @var AcmeError[] $subproblems */
    public readonly array $subproblems;

    /**
     * @param string $type
     * @param string|null $detail
     * @param int|null $httpCode
     * @param object $rawError
     */
    public function __construct(
        public readonly string $type,
        public readonly ?string $detail,
        public readonly ?int $httpCode,
        public readonly object $rawError
    )
    {
        $message = 'ACME error';
        if (empty($detail)) {
            $message .= ", type=$type";
        } else {
            $message .= ": $detail";
        }

        if (!empty($httpCode)) {
            $message .= ", httpCode=$httpCode";
        }

        if (!empty($rawError->subproblems) && is_array($rawError->subproblems)) {
            foreach ($rawError->subproblems as $subproblem) {
                if (isset($subproblem->type)) {
                    $this->subproblems[] = new self($subproblem->type, $subproblem->detail ?? null, $httpCode, $subproblem);
                }
            }
        }

        parent::__construct($message);
    }
}