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

try {
    // Check if 2FA is already enabled
    $stmt = $pdo->prepare("SELECT twofa_enabled FROM users WHERE id = ?");
    $stmt->execute([$user_id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user['twofa_enabled']) {
        echo json_encode(['success' => false, 'message' => 'Two-Factor Authentication is already enabled.']);
        exit;
    }

    // Generate new secret
    $g = new GoogleAuthenticator();
    $secret = $g->generateSecret();

    // Store secret temporarily in session
    $_SESSION['temp_2fa_secret'] = $secret;

    // Get user email for QR code
    $stmt = $pdo->prepare("SELECT email FROM users WHERE id = ?");
    $stmt->execute([$user_id]);
    $user_email = $stmt->fetchColumn();

    // Build a Google Authenticator compatible otpauth URI.
    $issuer = 'SecureAuth';
    $label = $issuer . ':' . $user_email;
    $otpauthUrl = 'otpauth://totp/' . rawurlencode($label)
        . '?secret=' . rawurlencode($secret)
        . '&issuer=' . rawurlencode($issuer);

    // Generate embeddable QR image URL from the otpauth URI.
    $qrImageUrl = 'https://api.qrserver.com/v1/create-qr-code/?size=300x300&data='
        . rawurlencode($otpauthUrl)
        . '&ecc=M';

    echo json_encode([
        'success' => true,
        'secret' => $secret,
        'qr_code_url' => $otpauthUrl,
        'qr_image_url' => $qrImageUrl
    ]);

} catch (Exception $e) {
    error_log('QR code generation error: ' . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'An error occurred while generating QR code.']);
}
?>