<?php

namespace test\config;

class CAConfig
{
    public readonly string $directoryUrl;
    public readonly string $email;
    /** @var string[] $domains */
    public readonly array $domains;
    /** @var string[] $ips */
    public readonly array $ips;
    public readonly ?EABConfig $externalAccountBinding;

    public function __construct(public readonly string $name, array $raw)
    {
        $this->directoryUrl = $raw['directoryUrl'];
        $this->email = $raw['email'];
        $this->domains = $raw['domains'];
        $this->ips = $raw['ips'];
        $this->externalAccountBinding = empty($raw['externalAccountBinding']) ? null : new EABConfig($raw['externalAccountBinding']);
    }
}