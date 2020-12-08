<?php

use pas9x\acme\Utils;

return [
    'timezone' => 'Asia/Irkutsk',
    'ca' => [
        'letsencrypt' => [
            'directoryUrl' => 'https://acme-staging-v02.api.letsencrypt.org/directory',
            'email' => 'spam@pascalhp.net',
            'domains' => [
                '75m.net',
                'www.75m.net',
            ],
            'docroot' => [
                '75m.net' => '/mnt/ssh/pashp_sites/www/75m.net/pub/',
                'www.75m.net' => '/mnt/ssh/pashp_sites/www/75m.net/pub/',
            ],
        ],
        'zerossl' => [
            'directoryUrl' => 'https://acme.zerossl.com/v2/DV90',
            'email' => 'spam@pascalhp.net',
            'domains' => [
                '75m.net',
                'www.75m.net',
            ],
            'externalAccountBinding' => [
                'kid' => '...',
                'key' => Utils::b64_urldecode('...'),
            ],
        ],
        'buypass' => [
            'directoryUrl' => 'https://api.test4.buypass.no/acme/directory',
            'email' => 'spam@pascalhp.net',
            'domains' => [
                '75m.net',
                'www.75m.net',
            ],
        ],
    ],
];