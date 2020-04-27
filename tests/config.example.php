<?php

return [
    'domains' => [
        '75m.net' => [
            'documentRoot' => '/mnt/ssh/pashp_sites/www/75m.net',
            'verifyMethod' => 'http', // or dns
        ],
        'www.75m.net' => [
            'documentRoot' => '/mnt/ssh/pashp_sites/www/75m.net',
            'verifyMethod' => 'http', // or dns
        ],
    ],
    'email' => 'murka@pascalhp.net',
    'directoryUrl' => 'https://acme-staging-v02.api.letsencrypt.org/directory',
];
