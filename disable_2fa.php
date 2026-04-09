<?php
session_start();
require_once 'db.php';
require_once 'email_config.php';
require_once 'csrf.php';

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
$password = $input['password'] ?? '';

if (empty($password)) {
    echo json_encode(['success' => false, 'message' => 'Password is required to disable 2FA.']);
    exit;
}

try {
    // Get user data
    $stmt = $pdo->prepare("SELECT email, password, twofa_enabled FROM users WHERE id = ?");
    $stmt->execute([$user_id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        echo json_encode(['success' => false, 'message' => 'User not found.']);
        exit;
    }

    if (!$user['twofa_enabled']) {
        echo json_encode(['success' => false, 'message' => 'Two-Factor Authentication is not enabled.']);
        exit;
    }

    // Verify password
    if (!password_verify($password, $user['password'])) {
        echo json_encode(['success' => false, 'message' => 'Incorrect password.']);
        exit;
    }

    // Begin transaction
    $pdo->beginTransaction();

    // Disable 2FA
    $stmt = $pdo->prepare("UPDATE users SET twofa_secret = NULL, twofa_enabled = 0 WHERE id = ?");
    $stmt->execute([$user_id]);

    // Delete backup codes
    $stmt = $pdo->prepare("DELETE FROM twofa_backup_codes WHERE user_id = ?");
    $stmt->execute([$user_id]);

    $pdo->commit();

    logActivity($pdo, $user_id, '2FA disabled');

    // Send email notification
    $subject = 'Two-Factor Authentication Disabled';
    $message = "
    <html>
    <head>
        <title>2FA Disabled</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 20px; border-radius: 0 0 10px 10px; }
            .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <div class='container'>
            <div class='header'>
                <h2>⚠️ 2FA Disabled</h2>
            </div>
            <div class='content'>
                <p>Hello,</p>
                <p>Two-Factor Authentication has been disabled for your SecureAuth account.</p>

                <div class='warning'>
                    <strong>Security Notice:</strong><br>
                    Your account is now less secure. We strongly recommend re-enabling Two-Factor Authentication as soon as possible.
                </div>

                <p><strong>Action Details:</strong></p>
                <ul>
                    <li>Time: " . date('Y-m-d H:i:s') . "</li>
                    <li>IP Address: " . $_SERVER['REMOTE_ADDR'] . "</li>
                </ul>

                <p>If you did not disable 2FA, please:</p>
                <ol>
                    <li>Change your password immediately</li>
                    <li>Re-enable Two-Factor Authentication</li>
                    <li>Contact our support team</li>
                </ol>

                <p>For your security, we recommend:</p>
                <ul>
                    <li>Always use strong, unique passwords</li>
                    <li>Enable Two-Factor Authentication</li>
                    <li>Regularly monitor your account activity</li>
                </ul>

                <p>If you have any questions, please don't hesitate to contact our support team.</p>

                <p>Best regards,<br>SecureAuth Security Team</p>
            </div>
        </div>
    </body>
    </html>
    ";

    sendEmail($user['email'], $subject, $message);

    echo json_encode(['success' => true, 'message' => 'Two-Factor Authentication has been disabled.']);

} catch (Exception $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    error_log('Disable 2FA error: ' . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'An error occurred while disabling 2FA.']);
}
?>