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
    //'directoryUrl' => 'https://acme-v02.api.letsencrypt.org/directory',

    /*
    'directoryUrl' => 'https://acme.zerossl.com/v2/DV90',
    'externalAccountBinding' => [
        'kid' => '... put here EAB KID ...',
        'key' => LetsEncryptInternals::b64_urldecode('... put here EAB HMAC Key ...'),
    ],
    */

    //'directoryUrl' => 'https://api.buypass.com/acme/directory',
    //'directoryUrl' => 'https://api.test4.buypass.no/acme/directory',
];
