<?php
require_once 'csrf.php';

header('Content-Type: application/json');

echo json_encode([
    'success' => true,
    'csrf_token' => csrf_token()
]);
