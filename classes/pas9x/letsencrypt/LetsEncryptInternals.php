<?php

namespace pas9x\letsencrypt;

use \Exception;
use \phpseclib\Crypt\Hash;
use \phpseclib\Crypt\RSA;
use \phpseclib\File\X509;

class LetsEncryptInternals
{
    const PEM_CERTIFICATE_REQUEST = 'CERTIFICATE REQUEST';
    const PEM_PRIVATE_KEY = 'PRIVATE KEY';
    const PEM_PUBLIC_KEY = 'PUBLIC KEY';

    /** @var LetsEncrypt $le */
    public $le;

    /** @var null|string */
    public $lastNonce = null;

    /** @var callable $onCurlExecute */
    public $onCurlExecute = null;

    public function __construct(LetsEncrypt $le)
    {
        $this->le = $le;
        $this->onCurlExecute = function(CurlRequest $curl) {
            $this->lastRequest = $curl;
            if (isset($this->lastRequest->responseHeaders['replay-nonce'])) {
                $this->lastNonce = $this->le->lastRequest->responseHeaders['replay-nonce'][0];
            }
        };
    }

    public function getNonce()
    {
        if (empty($this->lastNonce)) {
            $curl = $this->getCurl($this->le->getDirectory('newNonce'));
            $curl->curlOptions[CURLOPT_NOBODY] = 1;
            $curl->execute();
            if (empty($this->lastNonce)) {
                throw new Exception('Failed to acuire newNonce');
            }
        }
        $nonce = $this->lastNonce;
        $this->lastNonce = null;
        return $nonce;
    }

    public static function jsonDecode($json)
    {
        if (!is_string($json)) {
            throw new Exception('Invalid type of $json argument: ' . gettype($json));
        }
        if ($json === '') {
            throw new Exception('Attempt to jsonDecode for empty string');
        }
        $result = @json_decode($json, true);
        $errorCode = json_last_error();
        if ($errorCode !== JSON_ERROR_NONE) {
            $message = 'Failed to decode string as json';
            if (function_exists('json_last_error_msg')) {
                $message .= ': ' . json_last_error_msg();
            }
            $message .= " ($errorCode)";
            throw new Exception($message);
        }
        return $result;
    }

    /**
     * @param string $url
     * @return CurlRequest
     */
    public function getCurl($url)
    {
        $curl = new CurlRequest($url);
        if ($this->le->ignoreInvalidSsl) {
            $curl->ignoreInvalidSsl();
        }
        foreach ($this->le->curlOptions as $option => $value) {
            $curl->curlOptions[$option] = $value;
        }
        $curl->onDone[] = $this->onCurlExecute;
        $this->le->lastRequest = $curl;
        return $curl;
    }

    public static function b64_urlencode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    public static function b64_urldecode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * @param string $url
     * @param $signWith
     * @param array|object|null $payload
     * @return array
     * @throws Exception
     */
    public function formatRequest($url, $signWith, $payload = null)
    {
        if (empty($this->le->accountKeys)) {
            throw new Exception('No account private key. ' . get_class($this->le) . ' $accountKeys property is empty.');
        }

        $protected = [
            'alg' => 'RS256',
            'url' => $url,
            'nonce' => $this->getNonce(),
        ];
        if ($signWith === 'jwk') {
            $protected['jwk'] = $this->le->accountKeys->getJwk();
        } elseif ($signWith === 'kid') {
            if (empty($this->le->accountUrl)) {
                throw new Exception('Empty $kid property. You can acquire it after account registration.');
            }
            $protected['kid'] = $this->le->accountUrl;
        } else {
            throw new Exception('Invalid value of $signWith argument');
        }
        $protected_b64 = static::b64_urlencode(json_encode($protected));

        if ($payload === null) {
            $payload_b64 = '';
        } else {
            $payload_b64 = self::b64_urlencode(json_encode($payload));
        }

        $signed = $this->le->accountKeys->rsa->sign($protected_b64 . '.' . $payload_b64);
        $signed_b64 = static::b64_urlencode($signed);
        $result = [
            'protected' => $protected_b64,
            'payload' => $payload_b64,
            'signature' => $signed_b64
        ];
        return $result;
    }

    /**
     * @param string $url
     * @param string $signWith
     * @param null|array|object $payload
     */
    public function sendRequest($url, $signWith, $payload = null)
    {
        $request = $this->formatRequest($url, $signWith, $payload);
        $postdata = json_encode($request, JSON_PRETTY_PRINT);
        $curl = $this->getCurl($url);
        $curl->requestHeaders['Content-Type'] = 'application/jose+json';
        $curl->post($postdata);
        $curl->execute();
    }

    protected function throwIfError(array $response)
    {
        $httpCode = intval($this->le->lastRequest->responseCode);
        if (isset($response['type']) && $httpCode >= 400) {
            $type = $response['type'];
            $detail = isset($response['detail']) ? $response['detail'] : null;
            $exception = new AcmeError($type, $detail, $httpCode, $response);
            throw $exception;
        }
    }

    public function checkForError()
    {
        $response = @json_decode($this->le->lastRequest->responseBody, true);
        if (is_array($response)) {
            $this->throwIfError($response);
        }
    }

    public function getResponse()
    {
        try {
            $response = static::jsonDecode($this->le->lastRequest->responseBody);
        } catch (Exception $e) {
            throw new UnexpectedResponse($e->getMessage());
        }
        if (is_array($response)) {
            $this->throwIfError($response);
        }
        return $response;
    }

    /**
     * @param RSA|KeyPair|string|null $privateKey
     * @param string $email
     * @param string $primaryDomain
     * @param array $additionalDomains
     * @param array $additionalIPs
     * @param array $dnFields
     * @return CSR
     * @throws Exception
     */
    public static function generateCSR(
        $privateKey = null,
        $email,
        $primaryDomain,
        $additionalDomains = [],
        $additionalIPs = [],
        $dnFields = []
    )
    {
        if ($privateKey instanceof KeyPair) {
            $keys = $privateKey;
        } elseif ($privateKey instanceof RSA) {
            $keys = new KeyPair($privateKey);
        } elseif (is_string($privateKey)) {
            $keys = new KeyPair($privateKey);
        } elseif ($privateKey === null) {
            $keys = KeyPair::generate(2048);
        } else {
            throw new Exception('Invalid type of $privateKey argument: ' . gettype($privateKey));
        }

        $x509 = new X509;
        $x509->setPrivateKey($keys->rsa);
        $x509->setDNProp('commonname', $primaryDomain);
        $x509->setDNProp('emailaddress', $email);
        foreach ($dnFields as $name => $value) {
            $x509->setDNProp($name, $value);
        }

        $san = [];
        if (!empty($additionalDomains)) {
            foreach ($additionalDomains as $domain) {
                $san[] = ['dNSName' => $domain];
            }
        }
        if (!empty($additionalIPs)) {
            foreach ($additionalIPs as $ip) {
                $san[] = ['iPAddress' => $ip];
            }
        }
        if (!empty($san)) {
            $x509->currentCert = $x509->signCSR();
            $x509->setExtension('id-ce-subjectAltName', $san);
        }

        $csrStruct = $x509->signCSR();
        if (empty($csrStruct)) {
            throw new Exception('CSR generation failed (1)');
        }

        $result = new CSR;
        $result->keys = $keys;
        $result->der = $x509->saveCSR($csrStruct, X509::FORMAT_DER);
        $result->pem = static::derToPem($result->der, static::PEM_CERTIFICATE_REQUEST);
        if (empty($result->der)) {
            throw new Exception('CSR generation failed (2)');
        }
        return $result;
    }

    /**
     * @param string $objectClass
     * @param string $objectUrl
     * @return StatusBasedObject
     * @throws Exception
     */
    public function getObject($objectClass, $objectUrl)
    {
        if (!is_subclass_of($objectClass, '\pas9x\letsencrypt\StatusBasedObject')) {
            throw new Exception("$objectClass is not subclass of \pas9x\letsencrypt\StatusBasedObject");
        }
        $this->sendRequest($objectUrl, 'kid');
        $response = $this->getResponse();
        $result = new $objectClass($this, $objectUrl, $response);
        return $result;
    }

    /**
     * @param string $accountUrl
     * @return Account
     */
    public function getAccount($accountUrl)
    {
        /** @var Account $result */
        $result = $this->getObject('\pas9x\letsencrypt\Account', $accountUrl);
        return $result;
    }

    /**
     * @param string $orderUrl
     * @return Order
     */
    public function getOrder($orderUrl)
    {
        /** @var Order $result */
        $result = $this->getObject('\pas9x\letsencrypt\Order', $orderUrl);
        return $result;
    }

    /**
     * @param string $authzUrl
     * @return Authorization
     */
    public function getAuthorization($authzUrl)
    {
        /** @var Authorization $result */
        $result = $this->getObject('\pas9x\letsencrypt\Authorization', $authzUrl);
        return $result;
    }

    /**
     * @param string $challengeUrl
     * @return Challenge
     */
    public function getChallenge($challengeUrl)
    {
        /** @var Challenge $result */
        $result = $this->getObject('\pas9x\letsencrypt\Challenge', $challengeUrl);
        return $result;
    }

    /**
     * @param string $bytes
     * @param string $format binary|b64url
     * @return string
     * @throws Exception
     */
    public static function sha256($bytes, $format = 'binary')
    {
        $hasher = new Hash('sha256');
        $hash = $hasher->hash($bytes);
        if (!is_string($hash)) {
            throw new Exception('SHA256 calculation fail (1)');
        }
        if (strlen($hash) !== 32) {
            throw new Exception('SHA256 calculation fail (2)');
        }
        if ($format === 'binary') {
            return $hash;
        } elseif ($format = 'b64url') {
            return static::b64_urlencode($hash);
        } else {
            throw new Exception('Invalid $format');
        }
    }

    public static function normalizeEol($text)
    {
        $result = str_replace("\r\n", "\n", $text);
        $result = str_replace("\r", "\n", $result);
        return $result;
    }

    public static function derToPem($der, $header)
    {
        $result = "-----BEGIN $header-----\n";
        $result .= chunk_split(base64_encode($der), 64, "\n");
        $result .= "-----END $header-----";
        return $result;
    }

    public static function removeDash($pem)
    {
        $lines = explode("\n", static::normalizeEol($pem));
        foreach ($lines as $index => $line) {
            $trimmed = trim($line);
            if ($trimmed === '') unset($lines[$index]);
        }
        $lines = array_values($lines);
        $linesCount = count($lines);
        if ($linesCount < 3) {
            throw new Exception('Invalid PEM format (1)');
        }
        if (!preg_match('/^\-.+\-$/', $lines[0])) {
            throw new Exception('Invalid PEM format (2)');
        }
        if (!preg_match('/^\-.+\-$/', $lines[$linesCount - 1])) {
            throw new Exception('Invalid PEM format (3)');
        }
        unset($lines[0], $lines[$linesCount - 1]);
        foreach ($lines as $line) {
            if (!preg_match('/^[a-zA-Z0-9\+\/\=]+$/', $line)) {
                throw new Exception('Invalid PEM format (4)');
            }
        }
        return implode('', $lines);
    }

    public static function pemToDer($pem)
    {
        $der_b64 = static::removeDash($pem);
        $result = base64_decode($der_b64);
        return $result;
    }

    public static function getSubjectKeyIdentifier($certificatePem)
    {
        $x509 = new X509;
        $struct = $x509->loadX509($certificatePem, X509::FORMAT_PEM);
        if (empty($struct)) {
            return null;
        }
        $result = $x509->getExtension('id-ce-subjectKeyIdentifier');
        if (!is_string($result) || empty($result)) {
            return null;
        }
        return $result;
    }

    public static function getAuthorityKeyIdentifier($certificatePem)
    {
        $x509 = new X509;
        $struct = $x509->loadX509($certificatePem, X509::FORMAT_PEM);
        if (empty($struct)) {
            return null;
        }
        $value = $x509->getExtension('id-ce-authorityKeyIdentifier');
        if (empty($value['keyIdentifier'])) {
            return null;
        }
        $result = $value['keyIdentifier'];
        if (!is_string($result) || empty($result)) {
            return null;
        }
        return $result;
    }

    public static function checkCertificateChain(array $certificatePems)
    {
        $certs = array_values($certificatePems);
        if (empty($certs)) {
            return false;
        }
        foreach ($certs as $currentNumber => $currentCert) {
            $nextNumber = $currentNumber + 1;
            if (!isset($certs[$nextNumber])) {
                return true;
            }
            $nextCert = $certs[$nextNumber];
            $currentCertIssuerId = static::getAuthorityKeyIdentifier($currentCert);
            $nextCertId = static::getSubjectKeyIdentifier($nextCert);
            if (empty($currentCertIssuerId)) {
                throw new Exception('Failed to get authorityKeyIdentifier of certificate #' . $currentNumber);
            }
            if (empty($nextCertId)) {
                throw new Exception('Failed to get subjectKeyIdentifier of next certificate #' . $nextNumber);
            }
            if ($nextCertId !== $currentCertIssuerId) {
                return false;
            }
        }
        return true;
    }

    /**
     * @param string $text
     * @return string[]
     * @throws Exception
     */
    public static function parseCertificateChain($text)
    {
        $text = static::normalizeEol($text);
        preg_match_all('/\-+BEGIN CERTIFICATE\-+\s+(.+)\s+\-+END CERTIFICATE\-+/sU', $text, $matches);
        if (empty($matches[1])) {
            throw new Exception('Failed to parse text as certificate PEMs');
        }
        $result = [];
        foreach ($matches[1] as $der_b64) {
            $pem = "-----BEGIN CERTIFICATE-----\n";
            $pem .= trim($der_b64) . "\n";
            $pem .= "-----END CERTIFICATE-----";
            $result[] = $pem;
        }
        return $result;
    }

    /**
     * @param array $newFields
     * @return Account
     */
    public function saveAccount(array $newFields)
    {
        $this->sendRequest($this->le->accountUrl, 'kid', $newFields);
        $response = $this->getResponse();
        $accountUpdated = new Account($this, $this->le->accountUrl, $response);
        return $accountUpdated;
    }
}