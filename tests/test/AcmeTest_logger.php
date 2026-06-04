<?php

namespace test;

trait AcmeTest_logger
{
    public function log(string $message, mixed $details = null): void
    {
        echo trim($message) . "\n";
        if ($details !== null) {
            echo trim(print_r($details, true)) . "\n";
        }
    }
}