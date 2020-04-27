<?php

namespace pas9x\letsencrypt;

use \Exception;

abstract class DomainVerifierHttp implements DomainVerifier
{
    public $selfCheck = true;

    /** @inheritdoc */
    public function challengeType()
    {
        return 'http-01';
    }

    /** @inheritdoc */
    public function verify(VerificationData $verificationData)
    {
        $this->putFile($verificationData->fileUri, $verificationData->fileContent);
        if (!$this->selfCheck) {
            return;
        }
        $url = 'http://' . $this->domainName() . $verificationData->fileUri;
        $curl = new CurlRequest($url);
        $curl->execute();
        if ($curl->responseBody === $verificationData->fileContent) {
            return;
        }
        if ($curl->curlErrorCode !== CURLE_OK) {
            $message = 'Self-verification for domain ' . $this->domainName() . ' failed. cURL error: ';
            $message .= $curl->curlErrorMessage . ' (code ' . $curl->curlErrorCode . ')';
            throw new Exception($message);
        }
        $message = "Content of verification URL $url isn't match to valid verification file.";
        $message .= ' http_code=' . $curl->responseCode;
        if (!empty($curl->responseHeaders['content-type'][0])) {
            $message .= ', content_type=' . $curl->responseHeaders['content-type'][0];
        }
        throw new Exception($message);
    }

    public abstract function putFile($uri, $content);
}