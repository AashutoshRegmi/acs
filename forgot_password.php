<?php
require_once 'db.php';
require_once 'email_config.php';
require_once 'csrf.php';
require_once 'turnstile.php';

header('Content-Type: application/json');

// Rate limiting: Check if too many reset requests from this IP in the last hour
$ip_address = $_SERVER['REMOTE_ADDR'];
$one_hour_ago = date('Y-m-d H:i:s', strtotime('-1 hour'));

try {
    // Check rate limiting (max 3 requests per hour per IP)
    $stmt = $pdo->prepare("
        SELECT COUNT(*) as request_count
        FROM password_reset_tokens prt
        JOIN users u ON prt.user_id = u.id
        WHERE prt.created_at > ? AND u.last_ip = ?
    ");
    $stmt->execute([$one_hour_ago, $ip_address]);
    $result = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($result['request_count'] >= 3) {
        echo json_encode(['success' => false, 'message' => 'Too many password reset requests. Please try again in an hour.']);
        exit;
    }

} catch (Exception $e) {
    // Continue if rate limiting check fails
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'Invalid request method.']);
    exit;
}

if (!csrf_validate_request()) {
    echo json_encode(['success' => false, 'message' => 'Invalid security token. Please refresh and try again.']);
    exit;
}

// Get form data
$email = trim($_POST['email'] ?? '');
$cfTurnstileResponse = $_POST['cf-turnstile-response'] ?? '';

if (!verifyTurnstileToken($cfTurnstileResponse)) {
    echo json_encode(['success' => false, 'message' => 'CAPTCHA verification failed. Please try again.']);
    exit;
}

// Validate email
if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(['success' => false, 'message' => 'Please enter a valid email address.']);
    exit;
}

try {
    // Check if email exists and account is verified
    $stmt = $pdo->prepare("SELECT id, username, verified FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        // Don't reveal if email exists or not for security
        echo json_encode(['success' => true, 'message' => 'If an account with this email exists, a password reset link has been sent.']);
        exit;
    }

    if (!$user['verified']) {
        echo json_encode(['success' => false, 'message' => 'Please verify your email address first before resetting your password.']);
        exit;
    }

    // Generate secure reset token
    $reset_token = bin2hex(random_bytes(32));
    $expires_at = date('Y-m-d H:i:s', strtotime('+24 hours'));

    // Begin transaction
    $pdo->beginTransaction();

    // Invalidate any existing unused tokens for this user
    $stmt = $pdo->prepare("UPDATE password_reset_tokens SET used = TRUE WHERE user_id = ? AND used = FALSE");
    $stmt->execute([$user['id']]);

    // Insert new reset token
    $stmt = $pdo->prepare("INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)");
    $stmt->execute([$user['id'], $reset_token, $expires_at]);

    // Update user's last IP for rate limiting
    $stmt = $pdo->prepare("UPDATE users SET last_ip = ? WHERE id = ?");
    $stmt->execute([$ip_address, $user['id']]);

    $pdo->commit();

    // Send reset email
    $app_url = rtrim(env('APP_URL', ''), '/');
    if ($app_url === '') {
        $app_url = ((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\');
    }
    $reset_link = $app_url . "/reset_password.html?token=" . $reset_token;

    $subject = 'Password Reset Request';
    $message = "
    <html>
    <head>
        <title>Password Reset</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 20px; border-radius: 0 0 10px 10px; }
            .reset-button { display: inline-block; background: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; margin: 20px 0; }
            .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .footer { text-align: center; color: #666; font-size: 12px; margin-top: 20px; }
        </style>
    </head>
    <body>
        <div class='container'>
            <div class='header'>
                <h2>🔐 Password Reset Request</h2>
            </div>
            <div class='content'>
                <p>Hello <strong>{$user['username']}</strong>,</p>
                <p>You have requested to reset your password. Click the button below to reset your password:</p>

                <div style='text-align: center;'>
                    <a href='{$reset_link}' class='reset-button'>Reset My Password</a>
                </div>

                <div class='warning'>
                    <strong>Security Notice:</strong><br>
                    • This link will expire in 24 hours<br>
                    • You can only use this link once<br>
                    • If you didn't request this reset, please ignore this email
                </div>

                <p>If the button doesn't work, copy and paste this link into your browser:</p>
                <p><a href='{$reset_link}'>{$reset_link}</a></p>

                <p>For your security, we recommend:</p>
                <ul>
                    <li>Choose a strong, unique password</li>
                    <li>Never share your password with anyone</li>
                    <li>Enable two-factor authentication if available</li>
                </ul>

                <p>If you have any questions, please don't hesitate to contact our support team.</p>

                <p>Best regards,<br>SecureAuth Team</p>
            </div>
            <div class='footer'>
                This email was sent to {$email} at " . date('Y-m-d H:i:s') . "<br>
                If you didn't request this password reset, please ignore this email.
            </div>
        </div>
    </body>
    </html>
    ";

    sendEmail($email, $subject, $message);

    echo json_encode(['success' => true, 'message' => 'If an account with this email exists, a password reset link has been sent.']);

} catch (Exception $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    error_log('Password reset request error: ' . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'An error occurred while processing your request. Please try again.']);
}
?>