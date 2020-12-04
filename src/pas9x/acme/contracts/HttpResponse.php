<?php

namespace pas9x\acme\contracts;

interface HttpResponse
{
    /**
     * @return int
     */
    public function code(): int;

    /**
     * @return string[]
     */
    public function headers(): array;

    /**
     * @return string
     */
    public function body(): string;

    /**
     * @return string
     */
    public function __toString(): string;
}