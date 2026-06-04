<?php

return [
    'ca' => [
        'letsencrypt' => [
            'directoryUrl' => 'https://acme-staging-v02.api.letsencrypt.org/directory',
            'email' => 'you@gmail.com',
            'domains' => [
                'domain.com',
                'www.domain.com',
            ],
            'ips' => [
                '127.0.0.1',
            ],
        ],
    ],
    'httpClient' => 'native',
    //'httpClient' => 'guzzle',
    //'httpClient' => 'symfony',
];
