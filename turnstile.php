<?php
require_once 'env.php';

function verifyTurnstileToken($token) {
    if (!is_string($token) || trim($token) === '') {
        return false;
    }

    $secret = env('TURNSTILE_SECRET_KEY', '');
    if ($secret === '') {
        return false;
    }

    $url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
    $postData = [
        'secret' => $secret,
        'response' => $token,
        'remoteip' => $_SERVER['REMOTE_ADDR'] ?? ''
    ];

    $options = [
        'http' => [
            'header' => "Content-type: application/x-www-form-urlencoded\r\n",
            'method' => 'POST',
            'content' => http_build_query($postData),
            'timeout' => 10,
        ]
    ];

    $context = stream_context_create($options);
    $result = @file_get_contents($url, false, $context);
    if ($result === false) {
        return false;
    }

    $decoded = json_decode($result, true);
    return (bool)($decoded['success'] ?? false);
}
