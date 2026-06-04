<?php

namespace test;

use pas9x\acme\crypto\CSR;
use pas9x\acme\crypto\DistinguishedName;
use pas9x\acme\crypto\PrivateKeyEC;
use pas9x\acme\crypto\PrivateKeyRSA;
use pas9x\acme\dto\RegisteredCertificate;
use pas9x\acme\entity\Challenge;
use pas9x\acme\entity\Order;
use pas9x\acme\enums\KeyType;

trait AcmeTest_cert
{
    public function confirmWithWebroot()
    {
        $this->log('Confirming challenges with webroot');
        $order = $this->getOrder();

        if ($order->status === Order::STATUS_READY) {
            $this->log('Order status is already ready');
            return;
        }

        $authz = $order->getAuthorizations();
        $type = Challenge::VALIDATION_HTTP_01;
        foreach ($authz as $auth) {
            $domain = $auth->identifier->value;
            $challenge = $auth->getSpecificChallenge($type);
            if (empty($challenge)) {
                throw new TestFailedException("No challenge of type $type for $domain domain");
            }
            if ($challenge->status === Challenge::STATUS_VALID) {
                $this->log("$type challenge for domain $domain is already valid");
                continue;
            }
            if ($challenge->status === Challenge::STATUS_INVALID) {
                throw new TestFailedException("$type challenge for domain $domain is invalid");
            }
            if ($challenge->status === Challenge::STATUS_PENDING) {
                $data = $challenge->getVerificationData();
                echo "File upload need\n";
                echo "Path: {$data->file->dir}/{$data->file->fileName}\n";
                echo "Content: {$data->file->content}\n";
                echo "Upload the file and press [enter] ";
                fgets(STDIN);
                $url = "http://$domain{$data->file->dir}/{$data->file->fileName}";
                $content = file_get_contents($url);
                if ($content !== $data->file->content) {
                    throw new TestFailedException("Content of file $url does not match requested content");
                }
                $challenge->validate();
            }
            $timeout = 120;
            $deadline = time() + $timeout;
            $this->log("Wait $timeout for challenge validation of domain $domain");
            while (time() < $deadline) {
                sleep(3);
                $challenge->refresh();
                if ($challenge->status === Challenge::STATUS_VALID) {
                    $this->log("$type challenge for domain $domain is successfully validated");
                    continue 2;
                }
                if ($challenge->status === Challenge::STATUS_INVALID) {
                    throw new TestFailedException("$type challenge for domain $domain has failed");
                }
                if (in_array($challenge->status, [Challenge::STATUS_PENDING, Challenge::STATUS_PROCESSING])) {
                    continue;
                }
                throw new TestFailedException("Invalid challenge status {$challenge->status} for domain $domain");
            }
            throw new TestFailedException('Challenge validation timeout');
        }
    }

    public function registerCertificate(): RegisteredCertificate
    {
        $csrFile = BASEDIR . '/cert.csr';
        $keyFile = BASEDIR . '/cert.key';

        $order = $this->getOrder();
        if ($order->status === Order::STATUS_READY) {
            $csr = $this->generateCSR();
            file_put_contents($csrFile, $csr->csrPem);
            file_put_contents($keyFile, $csr->privateKey->getPrivateKeyPem());
            $order->registerCertificate($this->ca->domains[0], $csr);
        } elseif ($order->status = Order::STATUS_VALID) {
            $this->log('Certificate is already registered');
            return $this->downloadCertificate();
        } elseif ($order->status != Order::STATUS_PROCESSING) {
            throw new TestFailedException('Order status: ' . $order->status);
        }

        $timeout = 120;
        $deadline = time() + $timeout;
        while (time() < $deadline) {
            sleep(3);
            $order->refresh();
            if ($order->status === Order::STATUS_VALID) {
                $this->log('Certificate successfully registered');
                return $this->downloadCertificate();
            }
            if ($order->status !== Order::STATUS_PROCESSING) {
                throw new TestFailedException('Order status: ' . $order->status);
            }
        }

        throw new TestFailedException('Certificate registration timeout');
    }

    protected function downloadCertificate(): RegisteredCertificate
    {
        $order = $this->getOrder();
        $order->refresh(); // Sometimes there is no certificate download link
        $success = $order->downloadCertificate();
        file_put_contents(BASEDIR . '/cert.pem', $success->certificate->pem);
        $chain = implode("\n\n", $success->getChainPems());
        file_put_contents(BASEDIR . '/chain.pem', $chain);
        return $success;
    }

    protected function generateCSR(): CSR
    {
        if ($this->certificateKeyParams->keyType === KeyType::RSA) {
            $privateKey = PrivateKeyRSA::generate($this->certificateKeyParams->bits);
        } elseif ($this->certificateKeyParams->keyType === KeyType::EC) {
            $privateKey = PrivateKeyEC::generate($this->certificateKeyParams->curve);
        } else {
            throw new \LogicException('Unsupported certificate key type: ' . $this->certificateKeyParams->keyType->toString());
        }

        $dn = DistinguishedName::create($this->ca->domains[0]);
        $csr = CSR::generate($dn, $this->ca->domains, $this->ca->ips, $privateKey);
        return $csr;
    }
}