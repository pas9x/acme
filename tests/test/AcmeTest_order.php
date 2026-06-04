<?php

namespace test;

use pas9x\acme\crypto\PrivateKey;
use pas9x\acme\crypto\PrivateKeyEC;
use pas9x\acme\crypto\PrivateKeyRSA;
use pas9x\acme\entity\Order;
use pas9x\acme\enums\KeyType;

trait AcmeTest_order
{
    /** @var array<string,Order> $orders */
    private array $orders = [];

    public function getOrder(): Order
    {
        $existingOrder = $this->loadExistingOrder();
        if ($existingOrder !== null) {
            return $existingOrder;
        }
        return $this->getNewOrder();
    }

    public function getNewOrder(): Order
    {
        $account = $this->getAccount();
        $order = $account->newOrder($this->ca->domains);
        $this->log("New order: " . $order->getEntityUrl());
        $this->writeOrder($order);
        return $order;
    }

    protected function writeOrder(Order $order): void
    {
        $now = time();
        $info =[
            'url' => $order->getEntityUrl(),
            'create_time' => $now,
            'create_time_str' => date('d.m.Y H:i:s', $now),
        ];
        file_put_contents(BASEDIR . '/order.json', json_encode($info, JSON_PRETTY_PRINT));
    }

    protected function generatePrivateKey(KeyParams $params): PrivateKey
    {
        if ($params->keyType === KeyType::RSA) {
            return PrivateKeyRSA::generate($params->bits);
        }
        if ($params === KeyType::EC) {
            return PrivateKeyEC::generate($params->curve);
        }
        throw new \LogicException('Unsupported key type: ' . $params->keyType->toString());
    }

    protected function loadExistingOrder(): ?Order
    {
        $orderFile = BASEDIR . '/order.json';
        if (!is_file($orderFile)) {
            return null;
        }
        $json = file_get_contents($orderFile);
        $info = json_decode($json, false);
        if (empty($info) || !is_object($info)) {
            throw new \RuntimeException("Invalid content of file $orderFile");
        }

        if ((time() - $info->create_time) > 3600) {
            $this->log("Order {$info->url} is expired");
            $this->log("Delete file {$orderFile}");
            unlink($orderFile);
            return null;
        }

        return $this->getExistingOrder($info->url);
    }

    protected function getExistingOrder(string $orderEntityUrl): Order
    {
        $order = $this->orders[$orderEntityUrl] ?? null;
        if ($order !== null) {
            return $order;
        }
        $account = $this->getAccount();
        $this->orders[$orderEntityUrl] = $account->getOrder($orderEntityUrl);
        $this->log('Using existing order ' . $orderEntityUrl);
        return $this->orders[$orderEntityUrl];
    }
}