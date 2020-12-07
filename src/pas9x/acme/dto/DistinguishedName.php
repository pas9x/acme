<?php

namespace pas9x\acme\dto;

class DistinguishedName
{
    protected $commonName;
    protected $organizationName = '';
    protected $organizationalUnit = '';
    protected $locality = '';
    protected $state = '';
    protected $country = '';
    protected $emailAddress = '';

    public function __construct(string $commonName)
    {
        $this->commonName = $commonName;
    }

    public function commonName(string $newCommonName = null): string
    {
        if ($newCommonName !== null) {
            $this->commonName = $newCommonName;
        }
        return $this->commonName;
    }

    public function organizationName(string $newOrganizationName = null): string
    {
        if ($newOrganizationName !== null) {
            $this->organizationName = $newOrganizationName;
        }
        return $this->organizationName;
    }

    public function organizationalUnit(string $newOrganizationalUnit = null): string
    {
        if ($newOrganizationalUnit !== null) {
            $this->organizationalUnit = $newOrganizationalUnit;
        }
        return $this->organizationalUnit;
    }

    public function locality(string $newLocality = null): string
    {
        if ($newLocality !== null) {
            $this->locality = $newLocality;
        }
        return $this->locality;
    }

    public function state(string $newState = null): string
    {
        if ($newState !== null) {
            $this->state = $newState;
        }
        return $this->state;
    }

    public function country(string $newCountry = null): string
    {
        if ($newCountry !== null) {
            $this->country = $newCountry;
        }
        return $this->country;
    }

    public function emailAddress(string $newEmailAddress = null): string
    {
        if ($newEmailAddress !== null) {
            $this->emailAddress = $newEmailAddress;
        }
        return $this->emailAddress;
    }
}