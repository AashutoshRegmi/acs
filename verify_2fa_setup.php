<?php
session_start();
require_once 'db.php';
require_once 'vendor/autoload.php';
require_once 'csrf.php';

use Sonata\GoogleAuthenticator\GoogleAuthenticator;

header('Content-Type: application/json');

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    echo json_encode(['success' => false, 'message' => 'Please log in to access this feature.']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !csrf_validate_request()) {
    echo json_encode(['success' => false, 'message' => 'Security validation failed. Please refresh and try again.']);
    exit;
}

$user_id = $_SESSION['user_id'];

// Get POST data
$input = json_decode(file_get_contents('php://input'), true);
$code = $input['code'] ?? '';

if (empty($code) || !preg_match('/^[0-9]{6}$/', $code)) {
    echo json_encode(['success' => false, 'message' => 'Please enter a valid 6-digit verification code.']);
    exit;
}

try {
    // Check if temporary secret exists
    if (!isset($_SESSION['temp_2fa_secret'])) {
        echo json_encode(['success' => false, 'message' => 'No 2FA setup in progress. Please refresh the page and try again.']);
        exit;
    }

    $secret = $_SESSION['temp_2fa_secret'];

    // Verify the code
    $g = new GoogleAuthenticator();
    $isValid = $g->checkCode($secret, $code);

    if (!$isValid) {
        echo json_encode(['success' => false, 'message' => 'Invalid verification code. Please check your code and try again.']);
        exit;
    }

    // Code is valid, enable 2FA for user
    $stmt = $pdo->prepare("UPDATE users SET twofa_secret = ?, twofa_enabled = 1 WHERE id = ?");
    $stmt->execute([$secret, $user_id]);

    // Clear temporary secret
    unset($_SESSION['temp_2fa_secret']);

    logActivity($pdo, $user_id, '2FA enabled');

    echo json_encode(['success' => true, 'message' => 'Two-Factor Authentication has been successfully enabled!']);

} catch (Exception $e) {
    error_log('2FA verification error: ' . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'An error occurred during verification.']);
}
?>