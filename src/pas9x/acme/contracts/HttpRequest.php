<?php

namespace pas9x\acme\contracts;

interface HttpRequest
{
    /** @return string */
    public function method(): string;

    /** @return string */
    public function url(): string;

    /** @return string[] */
    public function headers(): array;

    /** @return mixed */
    public function postdata();

    /** @return string */
    public function __toString(): string;
}