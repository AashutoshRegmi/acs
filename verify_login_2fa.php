<?php
session_start();
require_once 'db.php';
require_once 'csrf.php';
require_once 'vendor/autoload.php';

use Sonata\GoogleAuthenticator\GoogleAuthenticator;

header('Content-Type: application/json');

// Check if user has pending 2FA verification
if (!isset($_SESSION['pending_2fa_user_id'])) {
    echo json_encode(['success' => false, 'message' => 'No pending 2FA verification found. Please log in again.']);
    exit;
}

if (!csrf_validate_request()) {
    echo json_encode(['success' => false, 'message' => 'Invalid security token. Please refresh and try again.']);
    exit;
}

$user_id = $_SESSION['pending_2fa_user_id'];

// Get POST data
$input = json_decode(file_get_contents('php://input'), true);
$code = trim($input['code'] ?? '');
$type = $input['type'] ?? 'authenticator';

if (empty($code)) {
    echo json_encode(['success' => false, 'message' => 'Verification code is required.']);
    exit;
}

try {
    // Get user data
    $stmt = $pdo->prepare("SELECT username, email, twofa_secret FROM users WHERE id = ?");
    $stmt->execute([$user_id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        echo json_encode(['success' => false, 'message' => 'User not found. Please try logging in again.']);
        exit;
    }

    $success = false;

    if ($type === 'authenticator') {
        // Verify Google Authenticator code
        if (empty($user['twofa_secret'])) {
            echo json_encode(['success' => false, 'message' => '2FA is not properly configured. Please contact support.']);
            exit;
        }

        $g = new GoogleAuthenticator();
        $success = $g->checkCode($user['twofa_secret'], $code);

        if (!$success) {
            echo json_encode(['success' => false, 'message' => 'Invalid authentication code. Please check your code and try again.']);
            exit;
        }
    } elseif ($type === 'backup') {
        // Verify backup code
        $stmt = $pdo->prepare("SELECT id FROM twofa_backup_codes WHERE user_id = ? AND code = ? AND used = FALSE");
        $stmt->execute([$user_id, $code]);
        $backup_code = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($backup_code) {
            // Mark backup code as used
            $stmt = $pdo->prepare("UPDATE twofa_backup_codes SET used = TRUE WHERE id = ?");
            $stmt->execute([$backup_code['id']]);
            $success = true;
        } else {
            echo json_encode(['success' => false, 'message' => 'Invalid or already used backup code.']);
            exit;
        }
    } else {
        echo json_encode(['success' => false, 'message' => 'Invalid verification type.']);
        exit;
    }

    if ($success) {
        session_regenerate_id(true);

        // Clear pending 2FA session data
        unset($_SESSION['pending_2fa_user_id']);
        unset($_SESSION['pending_2fa_username']);

        // Set user session
        $_SESSION['user'] = $user['username'];
        $_SESSION['user_id'] = $user_id;
        $_SESSION['username'] = $user['username'];
        $_SESSION['email'] = $user['email'];

        // Reset login attempts on successful login
        $stmt = $pdo->prepare("UPDATE users SET login_attempts = 0, locked_until = NULL WHERE id = ?");
        $stmt->execute([$user_id]);

        logActivity($pdo, $user_id, 'Login successful with 2FA');

        // Send login confirmation email
        require_once 'email_config.php';
        $subject = 'Successful Login to Your SecureAuth Account';
        $message = "
        <html>
        <head>
            <title>Login Successful</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: linear-gradient(135deg, #28a745 0%, #20c997 100%); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }
                .content { background: #f9f9f9; padding: 20px; border-radius: 0 0 10px 10px; }
                .success-icon { font-size: 48px; color: #28a745; text-align: center; margin: 20px 0; }
                .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }
            </style>
        </head>
        <body>
            <div class='container'>
                <div class='header'>
                    <h2>✅ Login Successful</h2>
                </div>
                <div class='content'>
                    <div class='success-icon'>🔐</div>

                    <p>Hello <strong>{$user['username']}</strong>,</p>
                    <p>You have successfully logged in to your SecureAuth account using Two-Factor Authentication.</p>

                    <div class='warning'>
                        <strong>Security Notice:</strong><br>
                        If this login was not initiated by you, please change your password immediately and contact support.
                    </div>

                    <p><strong>Login Details:</strong></p>
                    <ul>
                        <li>Time: " . date('Y-m-d H:i:s') . "</li>
                        <li>IP Address: " . $_SERVER['REMOTE_ADDR'] . "</li>
                        <li>Authentication Method: " . ($type === 'backup' ? 'Backup Code' : 'Google Authenticator') . "</li>
                    </ul>

                    <p>We recommend regularly monitoring your account activity and keeping your backup codes secure.</p>

                    <p>If you have any concerns about this login or your account security, please don't hesitate to contact our support team.</p>

                    <p>Best regards,<br>SecureAuth Security Team</p>
                </div>
            </div>
        </body>
        </html>
        ";

        sendEmail($user['email'], $subject, $message);

        echo json_encode(['success' => true, 'message' => 'Login successful! Welcome back.']);
    }

} catch (Exception $e) {
    error_log('Login 2FA verification error: ' . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'An error occurred during verification.']);
}
?>