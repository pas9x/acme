<?php

namespace pas9x\acme\crypto\helpers;

use pas9x\acme\Utils;

class X509ExtensionsParser
{
    public function __construct(protected readonly array $x509extensions)
    {
    }

    public function getExtensions(string $extnId): array
    {
        $result = [];
        foreach ($this->x509extensions as $ext) {
            if (!isset($ext['extnId'], $ext['extnValue'])) {
                continue;
            }
            if ($ext['extnId'] !== $extnId) {
                continue;
            }
            if (Utils::isNumericArray($ext['extnValue'])) {
                array_push($result, ...$ext['extnValue']);
            } else {
                $result[] = $ext['extnValue'];
            }
        }
        return $result;
    }

    public function getExtension(string $extnId): mixed
    {
        $extensions = $this->getExtensions($extnId);
        $count = count($extensions);
        if ($count < 1) {
            return null;
        }
        if ($count > 1) {
            throw new \RuntimeException("This certificate has $count $extnId extensions. Don't know which one to return.");
        }
        return $extensions[0];
    }
}