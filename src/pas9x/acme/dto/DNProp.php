<?php

namespace pas9x\acme\dto;

use pas9x\acme\crypto\DistinguishedName;

class DNProp
{
    public function __construct(
        public readonly string $oid,
        public readonly string $value,
        public readonly ?string $name
    )
    {
    }

    public function getName(): ?string
    {
        return DistinguishedName::getNameByOid($this->oid);
    }
}