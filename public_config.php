<?php
require_once 'env.php';

header('Content-Type: application/json');

echo json_encode([
    'turnstileSiteKey' => env('TURNSTILE_SITE_KEY', '')
]);
