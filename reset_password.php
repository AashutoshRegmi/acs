<?php
require_once 'db.php';
require_once 'email_config.php';
require_once 'csrf.php';
require_once 'turnstile.php';

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'Invalid request method.']);
    exit;
}

if (!csrf_validate_request()) {
    echo json_encode(['success' => false, 'message' => 'Invalid security token. Please refresh and try again.']);
    exit;
}

// Get form data
$token = trim($_POST['token'] ?? '');
$new_password = trim($_POST['new_password'] ?? '');
$confirm_password = trim($_POST['confirm_password'] ?? '');
$cfTurnstileResponse = $_POST['cf-turnstile-response'] ?? '';

if (!verifyTurnstileToken($cfTurnstileResponse)) {
    echo json_encode(['success' => false, 'message' => 'CAPTCHA verification failed. Please try again.']);
    exit;
}

// Validate token
if (empty($token)) {
    echo json_encode(['success' => false, 'message' => 'Invalid reset token.']);
    exit;
}

// Validate input
if (empty($new_password) || empty($confirm_password)) {
    echo json_encode(['success' => false, 'message' => 'All fields are required.']);
    exit;
}

if ($new_password !== $confirm_password) {
    echo json_encode(['success' => false, 'message' => 'Passwords do not match.']);
    exit;
}

// Password strength validation
if (!validatePasswordStrength($new_password)) {
    echo json_encode(['success' => false, 'message' => 'Password does not meet security requirements.']);
    exit;
}

try {
    // Get and validate reset token
    $stmt = $pdo->prepare("
        SELECT prt.*, u.email, u.username, u.password
        FROM password_reset_tokens prt
        JOIN users u ON prt.user_id = u.id
        WHERE prt.token = ? AND prt.used = FALSE AND prt.expires_at > NOW()
    ");
    $stmt->execute([$token]);
    $reset_data = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$reset_data) {
        echo json_encode(['success' => false, 'message' => 'Invalid or expired reset token. Please request a new password reset.']);
        exit;
    }

    $user_id = $reset_data['user_id'];
    $user_email = $reset_data['email'];
    $user_username = $reset_data['username'];

    // Check password history (prevent reuse of last 5 passwords)
    $stmt = $pdo->prepare("SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY changed_at DESC LIMIT 5");
    $stmt->execute([$user_id]);
    $password_history = $stmt->fetchAll(PDO::FETCH_COLUMN);

    foreach ($password_history as $old_hash) {
        if (password_verify($new_password, $old_hash)) {
            echo json_encode(['success' => false, 'message' => 'You cannot reuse a recent password. Please choose a different password.']);
            exit;
        }
    }

    // Check if new password is same as current
    if (password_verify($new_password, $reset_data['password'])) {
        echo json_encode(['success' => false, 'message' => 'New password must be different from your current password.']);
        exit;
    }

    // Hash new password
    $new_password_hash = password_hash($new_password, PASSWORD_DEFAULT);

    // Begin transaction
    $pdo->beginTransaction();

    // Move current password to history
    $stmt = $pdo->prepare("INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)");
    $stmt->execute([$user_id, $reset_data['password']]);

    // Update user password and reset security fields
    $stmt = $pdo->prepare("
        UPDATE users SET
            password = ?,
            password_changed_at = NOW(),
            login_attempts = 0,
            locked_until = NULL
        WHERE id = ?
    ");
    $stmt->execute([$new_password_hash, $user_id]);

    // Mark reset token as used
    $stmt = $pdo->prepare("UPDATE password_reset_tokens SET used = TRUE WHERE token = ?");
    $stmt->execute([$token]);

    // Clean up old password history (keep only last 5)
    $stmt = $pdo->prepare("
        DELETE FROM password_history
        WHERE user_id = ? AND id NOT IN (
            SELECT id FROM (
                SELECT id FROM password_history
                WHERE user_id = ?
                ORDER BY changed_at DESC LIMIT 5
            ) AS temp
        )
    ");
    $stmt->execute([$user_id, $user_id]);

    $pdo->commit();

    // Send confirmation email
    $subject = 'Password Reset Successful';
    $message = "
    <html>
    <head>
        <title>Password Reset Successful</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 20px; border-radius: 0 0 10px 10px; }
            .success-icon { font-size: 48px; color: #28a745; text-align: center; margin: 20px 0; }
            .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <div class='container'>
            <div class='header'>
                <h2>🔐 Password Reset Successful</h2>
            </div>
            <div class='content'>
                <div class='success-icon'>✅</div>

                <p>Hello <strong>{$user_username}</strong>,</p>
                <p>Your password has been successfully reset!</p>

                <div class='warning'>
                    <strong>Security Notice:</strong><br>
                    If you did not perform this password reset, please contact support immediately and consider changing your password again.
                </div>

                <p><strong>Reset Details:</strong></p>
                <ul>
                    <li>Time: " . date('Y-m-d H:i:s') . "</li>
                    <li>IP Address: " . $_SERVER['REMOTE_ADDR'] . "</li>
                </ul>

                <p>You can now log in to your account using your new password.</p>

                <p>For your security, we recommend:</p>
                <ul>
                    <li>Using a unique password for this account</li>
                    <li>Never share your password with anyone</li>
                    <li>Regularly monitoring your account activity</li>
                    <li>Enabling two-factor authentication if available</li>
                </ul>

                <p>If you have any questions or concerns, please don't hesitate to contact our support team.</p>

                <p>Best regards,<br>SecureAuth Team</p>
            </div>
        </div>
    </body>
    </html>
    ";

    sendEmail($user_email, $subject, $message);

    echo json_encode([
        'success' => true,
        'message' => 'Password reset successful! You can now log in with your new password.'
    ]);

} catch (Exception $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    error_log('Password reset error: ' . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'An error occurred while resetting your password. Please try again.']);
}

function validatePasswordStrength($password) {
    // Length: 8-12 characters
    if (strlen($password) < 8 || strlen($password) > 12) {
        return false;
    }

    // At least one uppercase letter
    if (!preg_match('/[A-Z]/', $password)) {
        return false;
    }

    // At least one lowercase letter
    if (!preg_match('/[a-z]/', $password)) {
        return false;
    }

    // At least one number
    if (!preg_match('/\d/', $password)) {
        return false;
    }

    // At least one special character
    if (!preg_match('/[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]/', $password)) {
        return false;
    }

    return true;
}
?>