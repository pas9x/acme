<?php

namespace pas9x\letsencrypt;

use \Exception;
use \phpseclib\Crypt\RSA;
use \phpseclib\File\X509;

/**
 * Todo: сделать поддержку множественных ошибок subproblems
 * Todo: сделать нормальное вычисление иерархии цепочки сертификатов
 * Class LetsEncrypt
 * @package pas9x\letsencrypt
 */

class LetsEncrypt
{
    //public $directoryURL = 'https://acme-staging-v02.api.letsencrypt.org/directory';
    /** @var string $directoryURL */
    public $directoryURL = 'https://acme-v02.api.letsencrypt.org/directory';

    /** @var array $directory */
    public $directory = [];

    /** @var KeyPair $accountKeys */
    public $accountKeys = null;

    /** @var string|null $accountUrl */
    public $accountUrl;

    /** @var array $curlOptions */
    public $curlOptions = [];

    /** @var bool $ignoreInvalidSsl */
    public $ignoreInvalidSsl = false;

    /** @var CurlRequest|null $lastRequest */
    public $lastRequest = null;

    const REVOCATION_REASON_UNSPECIFIED = 0;
    const REVOCATION_REASON_KEY_COMPROMISE = 1;
    const REVOCATION_REASON_CA_COMPROMISE = 2;
    const REVOCATION_REASON_AFFILIATION_CHANGED = 3;
    const REVOCATION_REASON_SUPERSEDED = 4;
    const REVOCATION_REASON_CESSATION_OF_OPERATION = 5;
    const REVOCATION_REASON_CERTIFICATE_HOLD = 6;
    const REVOCATION_REASON_REMOVE_FROM_CRL = 8;
    const REVOCATION_REASON_PRIVILEGE_WITHDRAWN = 9;
    const REVOCATION_REASON_AA_COMPROMISE = 10;

    protected static $revocationReasons = [
        self::REVOCATION_REASON_UNSPECIFIED,
        self::REVOCATION_REASON_KEY_COMPROMISE,
        self::REVOCATION_REASON_CA_COMPROMISE,
        self::REVOCATION_REASON_AFFILIATION_CHANGED,
        self::REVOCATION_REASON_SUPERSEDED,
        self::REVOCATION_REASON_CESSATION_OF_OPERATION,
        self::REVOCATION_REASON_CERTIFICATE_HOLD,
        self::REVOCATION_REASON_REMOVE_FROM_CRL,
        self::REVOCATION_REASON_PRIVILEGE_WITHDRAWN,
        self::REVOCATION_REASON_AA_COMPROMISE,
    ];

    /** @var LetsEncryptEntrails $entrails */
    public $entrails;

    public function __construct(KeyPair $accountKeys = null, $accountUrl = null)
    {
        if (!class_exists('\phpseclib\Crypt\RSA')) {
            throw new Exception('phpseclib not found');
        }
        $this->accountKeys = $accountKeys;
        $this->accountUrl = $accountUrl;
        $this->entrails = new LetsEncryptEntrails($this);
    }

    /**
     * @param null|string $service
     * @return array|string
     * @throws Exception
     */
    public function getDirectory($service = null)
    {
        if (empty($this->directory) || !is_array($this->directory)) {
            $curl = $this->entrails->getCurl($this->directoryURL);
            $curl->execute();
            $directory = LetsEncryptEntrails::jsonDecode($curl->responseBody);
            if (!is_array($directory) || empty($directory)) {
                throw new Exception('No directory found on ' . $this->directoryURL);
            }
            $needResources = ['newNonce', 'newAccount', 'newOrder', 'revokeCert', 'keyChange'];
            foreach ($needResources as $resource) {
                if (empty($directory[$resource])) {
                    throw new Exception("Directory has no `$resource` resource");
                }
            }
            $this->directory = $directory;
        }
        if ($service === null) {
            return $this->directory;
        }
        if (isset($this->directory[$service])) {
            return $this->directory[$service];
        }
        throw new Exception("Service `$service` not found in directory");
    }

    /**
     * @param string $email
     * @param bool $termsOfServiceAgreed
     * @param bool $onlyReturnExisting
     * @return Account
     * @throws Exception
     * @throws UnexpectedResponse
     */
    public function registerAccount($email, $termsOfServiceAgreed, $onlyReturnExisting = false)
    {
        if (!empty($this->accountUrl)) {
            throw new Exception('$kid property is not empty. Clear it first before register account.');
        }
        if (empty($this->accountKeys)) {
            $this->accountKeys = KeyPair::generate(2048);
        }
        $payload = [
            'termsOfServiceAgreed' => $termsOfServiceAgreed,
            'onlyReturnExisting' => $onlyReturnExisting,
            'contact' => ["mailto:$email"],
        ];
        $this->entrails->postWithPayload($this->getDirectory('newAccount'), $payload, 'jwk');
        $response = $this->entrails->getResponse();
        if (!isset($this->lastRequest->responseHeaders['location'][0])) {
            throw new UnexpectedResponse('No `location` response header');
        }
        $account = new Account($this->entrails, $this->lastRequest->responseHeaders['location'][0], $response);
        $this->accountUrl = $account->url;
        return $account;
    }

    /**
     * @param null|string $accountUrl
     * @return Account
     * @throws Exception
     */
    public function getAccount($accountUrl = null)
    {
        if ($accountUrl === null) {
            $accountUrl = $this->accountUrl;
            if ($accountUrl === null) {
                throw new Exception('No account url');
            }
        }
        $result = $this->entrails->getAccount($accountUrl);
        return $result;
    }

    /**
     * @param string[] $domains
     * @return Order
     * @throws UnexpectedResponse
     */
    public function newOrder(array $domains)
    {
        $payload = [
            'identifiers' => [],
        ];
        foreach ($domains as $domain) {
            $payload['identifiers'][] = ['type' => 'dns', 'value' => $domain];
        }
        $this->entrails->postWithPayload($this->getDirectory('newOrder'), $payload, 'kid');
        $response = $this->entrails->getResponse();
        if (!isset($this->lastRequest->responseHeaders['location'][0])) {
            throw new UnexpectedResponse('No order Location header in server response. http_code=' . $this->lastRequest->responseCode);
        }
        $result = new Order($this->entrails, $this->lastRequest->responseHeaders['location'][0], $response);
        return $result;
    }

    /**
     * @param $orderUrl
     * @return Order
     * @throws UnexpectedResponse
     */
    public function getOrder($orderUrl)
    {
        $result = $this->entrails->getOrder($orderUrl);
        return $result;
    }

    /**
     * @param string $email
     * @param DomainVerifier $primaryDomain
     * @param DomainVerifier[] $additionalDomains
     * @param string[] $distinguishedNameFields
     * @param int $timeout
     * @param callable|null $onStatus
     * @return Certificate
     * @throws Exception
     */
    public function registerCertificate(
        $email,
        DomainVerifier $primaryDomain,
        array $additionalDomains,
        array $distinguishedNameFields,
        $timeout = 60,
        callable $onStatus = null
    )
    {
        $deadline = time() + $timeout;
        $isTimedOut = function() use($deadline) {
            return time() < $deadline;
        };

        $callback = is_callable($onStatus) ? $onStatus : function(){};
        $notify = function($id, $message = null, $additional = null) use($callback) {
            return $callback($id, $message, $additional);
        };

        /** @var DomainVerifier[] $verifiers */
        $verifiers = [
            $primaryDomain->domainName() => $primaryDomain,
        ];
        foreach ($additionalDomains as $verifier) {
            $verifiers[$verifier->domainName()] = $verifier;
        }
        $domains = array_keys($verifiers);

        $notify('newOrder-begin', 'Getting new order...');
        $order = $this->newOrder($domains);
        $status = $order->getStatus();
        if ($status === 'ready') {
            goto ready;
        }
        if ($status !== 'pending') {
            throw new Exception("New order has status `$status` but expected is `pending`");
        }
        $notify('newOrder-end', 'Order url is ' . $order->url);

        $domainsVerificationData = $order->getDomainsVerificationData();

        $notify('verifiers-begin', 'Working with verifiers...');
        foreach ($verifiers as $domain => $verifier) {
            $notify('verify-domain', "Applying verification for domain $domain", $domain);
            if (!isset($domainsVerificationData[$domain])) {
                throw new Exception('No verification data for domain ' . $domain);
            }
            $domainVerificationData = $domainsVerificationData[$domain];
            try {
                $verifier->verify($domainVerificationData);
            } catch (Exception $e) {
                throw new Exception("Verification of domain $domain failed: " . $e->getMessage());
            }
        }
        $notify('verifiers-end', 'Applying verification for domains done');

        $notify('authorizations-begin', 'Asking ACME server for domains verification...');
        foreach ($order->getAuthorizations() as $authz) {
            $authzDomain = $authz->getDomain();
            $notify('authorization', "Asking ACME server to verify domain $authzDomain", $authzDomain);
            if (isset($verifiers[$authzDomain])) {
                $verifier = $verifiers[$authzDomain];
            } else {
                throw new Exception('No verifier for domain ' . $authzDomain);
            }
            $challenge = $authz->getChallenge($verifier->challengeType());
            if (empty($challenge)) {
                throw new Exception("Domain $authzDomain has verifier with challengeType=" . $verifier->challengeType() . ", but its authorization has no such challenge");
            }
            $challenge->validate();
        }
        $notify('authorizations-end', 'Domains verification requests are sent');

        $notify('decisionWait-begin', 'Waiting for ACME server decision...');
        while (!$order->isReadyToCertificateRegistration(true)) {
            if ($isTimedOut()) {
                throw new Exception("Timeout {$timeout}sec reached on waiting for domains verification");
            }
            $notify('decisionWait', 'ACME server still not made all checks. Keep waiting...');
            sleep(10);
        }
        $notify('decisionWait-end', 'Fine! ACME server allowed to register certificate');

        ready:
        $notify('regRequest-begin', 'Sending request for certificate registration...');
        $csr = $order->commitCertificateRegistration($primaryDomain->domainName(), $email, $distinguishedNameFields);
        $notify('regRequest-end', 'Certificate registration request are sent');

        $notify('registrationWait-begin', 'Waiting for certificate registration...');
        while (!$order->isRegistrationComplete(true)) {
            if ($isTimedOut()) {
                throw new Exception("Timeout {$timeout}sec reached on waiting for certificate registration");
            }
            $notify('registrationWait', 'ACME server still not registered the certificate. Keep waiting...');
            sleep(10);
        }
        $notify('registrationWait-end', 'Certificate registration complete');

        $notify('certificateDownload-begin', 'Downloading certificate...');
        $chain = $order->downloadCertificate();
        $result = new Certificate;
        $result->order = $order;
        $result->chain = $chain;
        $result->csr = $csr;
        $result->keys = $csr->keys;
        $notify('certificateDownload-end', 'Congratulations! Your certificate is ready', $result);

        foreach ($verifiers as $verifier) {
            $domain = $verifier->domainName();
            try {
                $verifier->cleanup();
            } catch (Exception $exception) {
                $additional = compact('domain', 'exception');
                $notify('cleanupFail', "Failed to cleanup verification for domain $domain: " . $exception->getMessage(), $additional);
            }
        }

        return $result;
    }

    /**
     * @param string|Certificate $certificate Certificate PEM or object
     * @param int $reason
     * @throws Exception
     */
    public function revokeCertificate($certificate, $reason = 0)
    {
        if (!in_array($reason, static::$revocationReasons, true)) {
            throw new Exception('Invalid value of $reason argument');
        }

        if ($certificate instanceof Certificate) {
            if (empty($certificate->chain[0])) {
                throw new Exception('Nothing at index #0 of certificate chain');
            }
            $der = LetsEncryptEntrails::pemToDer($certificate->chain[0]);
        } elseif (is_string($certificate)) {
            $der = LetsEncryptEntrails::pemToDer($certificate);
        } else {
            throw new Exception('Invalid type of $certificate argument');
        }

        $payload = [
            'certificate' => LetsEncryptEntrails::b64_urlencode($der),
        ];
        if ($reason !== static::REVOCATION_REASON_UNSPECIFIED) {
            $payload['reason'] = $reason;
        }

        $this->entrails->postWithPayload($this->getDirectory('revokeCert'), $payload, 'kid');
        $this->entrails->checkForError();
    }

    public function deactivateVerification(array $domains)
    {
        $order = $this->newOrder($domains);
        $order->deactivateVerification();
    }
}