<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

function csrf_token() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf_token'];
}

function csrf_validate_request() {
    $expected = $_SESSION['csrf_token'] ?? '';
    if ($expected === '') {
        return false;
    }

    $provided = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($_POST['_csrf'] ?? '');
    if (!is_string($provided) || $provided === '') {
        return false;
    }

    return hash_equals($expected, $provided);
}
