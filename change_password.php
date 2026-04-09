<?php
session_start();
require_once 'db.php';
require_once 'email_config.php';
require_once 'csrf.php';

header('Content-Type: application/json');

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    echo json_encode(['success' => false, 'message' => 'Please log in to change your password.']);
    exit;
}

$user_id = $_SESSION['user_id'];

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'Invalid request method.']);
    exit;
}

if (!csrf_validate_request()) {
    echo json_encode(['success' => false, 'message' => 'Invalid security token. Please refresh and try again.']);
    exit;
}

// Get form data
$current_password = trim($_POST['current_password'] ?? '');
$new_password = trim($_POST['new_password'] ?? '');
$confirm_password = trim($_POST['confirm_password'] ?? '');

// Validate input
if (empty($current_password) || empty($new_password) || empty($confirm_password)) {
    echo json_encode(['success' => false, 'message' => 'All fields are required.']);
    exit;
}

if ($new_password !== $confirm_password) {
    echo json_encode(['success' => false, 'message' => 'New passwords do not match.']);
    exit;
}

// Password strength validation
if (!validatePasswordStrength($new_password)) {
    echo json_encode(['success' => false, 'message' => 'Password does not meet security requirements.']);
    exit;
}

try {
    // Get user data
    $stmt = $pdo->prepare("SELECT email, password, login_attempts, locked_until, password_changed_at FROM users WHERE id = ?");
    $stmt->execute([$user_id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        echo json_encode(['success' => false, 'message' => 'User not found.']);
        exit;
    }

    // Check if account is locked
    if ($user['locked_until'] && strtotime($user['locked_until']) > time()) {
        echo json_encode(['success' => false, 'message' => 'Account is temporarily locked due to too many failed attempts.']);
        exit;
    }

    // Verify current password
    if (!password_verify($current_password, $user['password'])) {
        // Increment login attempts
        $new_attempts = $user['login_attempts'] + 1;
        $locked_until = null;

        if ($new_attempts >= 5) {
            $locked_until = date('Y-m-d H:i:s', strtotime('+15 minutes'));
        }

        $stmt = $pdo->prepare("UPDATE users SET login_attempts = ?, locked_until = ? WHERE id = ?");
        $stmt->execute([$new_attempts, $locked_until, $user_id]);

        echo json_encode(['success' => false, 'message' => 'Current password is incorrect.']);
        exit;
    }

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
    if (password_verify($new_password, $user['password'])) {
        echo json_encode(['success' => false, 'message' => 'New password must be different from your current password.']);
        exit;
    }

    // Rate limiting: Check if password was changed recently (within last hour)
    // But allow changes if password is expired (older than 30 days)
    $passwordExpired = $user['password_changed_at'] && strtotime($user['password_changed_at']) < strtotime('-30 days');
    if (!$passwordExpired && $user['password_changed_at'] && strtotime($user['password_changed_at']) > strtotime('-1 hour')) {
        echo json_encode(['success' => false, 'message' => 'Password can only be changed once per hour. Please try again later.']);
        exit;
    }

    // Hash new password
    $new_password_hash = password_hash($new_password, PASSWORD_DEFAULT);

    // Begin transaction
    $pdo->beginTransaction();

    // Move current password to history
    $stmt = $pdo->prepare("INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)");
    $stmt->execute([$user_id, $user['password']]);

    // Update user password and reset security fields
    $stmt = $pdo->prepare("UPDATE users SET password = ?, password_changed_at = NOW(), login_attempts = 0, locked_until = NULL WHERE id = ?");
    $stmt->execute([$new_password_hash, $user_id]);

    // Clean up old password history (keep only last 5)
    $stmt = $pdo->prepare("DELETE FROM password_history WHERE user_id = ? AND id NOT IN (SELECT id FROM (SELECT id FROM password_history WHERE user_id = ? ORDER BY changed_at DESC LIMIT 5) AS temp)");
    $stmt->execute([$user_id, $user_id]);

    $pdo->commit();

    logActivity($pdo, $user_id, 'Password changed');

    // Send email notification
    $subject = 'Password Changed Successfully';
    $message = "
    <html>
    <head>
        <title>Password Changed</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 20px; border-radius: 0 0 10px 10px; }
            .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <div class='container'>
            <div class='header'>
                <h2>🔐 Password Changed</h2>
            </div>
            <div class='content'>
                <p>Hello,</p>
                <p>Your password has been successfully changed.</p>

                <div class='warning'>
                    <strong>Security Notice:</strong><br>
                    If you did not make this change, please contact support immediately and consider changing your password again.
                </div>

                <p><strong>Change Details:</strong></p>
                <ul>
                    <li>Time: " . date('Y-m-d H:i:s') . "</li>
                    <li>IP Address: " . $_SERVER['REMOTE_ADDR'] . "</li>
                </ul>

                <p>For your security, we recommend:</p>
                <ul>
                    <li>Using a unique password for this account</li>
                    <li>Enabling two-factor authentication if available</li>
                    <li>Regularly monitoring your account activity</li>
                </ul>

                <p>If you have any questions, please don't hesitate to contact our support team.</p>

                <p>Best regards,<br>SecureAuth Team</p>
            </div>
        </div>
    </body>
    </html>
    ";

    sendEmail($user['email'], $subject, $message);

    // Destroy all other sessions for security
    session_regenerate_id(true);

    echo json_encode([
        'success' => true,
        'message' => 'Password changed successfully! You will be redirected to the dashboard.'
    ]);

} catch (Exception $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    error_log('Password change error: ' . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'An error occurred while changing your password. Please try again.']);
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