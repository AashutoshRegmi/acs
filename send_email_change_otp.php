<?php
session_start();
require_once 'db.php';
require_once 'email_config.php';
require_once 'csrf.php';

header('Content-Type: application/json');

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    echo json_encode(['success' => false, 'message' => 'Please log in to change your email.']);
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

// Get POST data
$input = json_decode(file_get_contents('php://input'), true);
$new_email = trim($input['new_email'] ?? '');
$is_resend = isset($input['resend']) && $input['resend'];

if (empty($new_email)) {
    echo json_encode(['success' => false, 'message' => 'New email address is required.']);
    exit;
}

// Validate email format
if (!filter_var($new_email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(['success' => false, 'message' => 'Please enter a valid email address.']);
    exit;
}

try {
    // Get current user data including 2FA status
    $stmt = $pdo->prepare("SELECT email, twofa_enabled FROM users WHERE id = ?");
    $stmt->execute([$user_id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        echo json_encode(['success' => false, 'message' => 'User not found.']);
        exit;
    }

    $current_email = $user['email'];

    // Check if 2FA is enabled - require disabling it first
    if ($user['twofa_enabled']) {
        echo json_encode([
            'success' => false,
            'message' => 'Two-Factor Authentication must be disabled before changing your email address. Please go to the 2FA settings and disable 2FA first.',
            'requires_2fa_disable' => true
        ]);
        exit;
    }

    // Check if new email is different from current
    if ($new_email === $current_email) {
        echo json_encode(['success' => false, 'message' => 'New email must be different from current email.']);
        exit;
    }

    // Check if new email is already taken by another user
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ? AND id != ?");
    $stmt->execute([$new_email, $user_id]);
    if ($stmt->fetch()) {
        echo json_encode(['success' => false, 'message' => 'This email address is already registered.']);
        exit;
    }

    // Generate OTP codes
    $current_email_otp = str_pad(rand(0, 999999), 6, '0', STR_PAD_LEFT);
    $new_email_otp = str_pad(rand(0, 999999), 6, '0', STR_PAD_LEFT);
    $otp_expires = date('Y-m-d H:i:s', strtotime('+10 minutes'));

    // Store OTP data in session
    $_SESSION['email_change_otp'] = [
        'current_email_otp' => $current_email_otp,
        'new_email_otp' => $new_email_otp,
        'new_email' => $new_email,
        'expires' => $otp_expires
    ];

    // Send OTP to current email
    $subject = 'Email Change Verification - Current Email';
    $message = "
    <html>
    <head>
        <title>Email Change Verification</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #ffc107 0%, #fd7e14 100%); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 20px; border-radius: 0 0 10px 10px; }
            .otp-code { background: #fff; border: 2px solid #D4AF37; padding: 15px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 5px; margin: 20px 0; }
            .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <div class='container'>
            <div class='header'>
                <h2>🔐 Email Change Verification</h2>
            </div>
            <div class='content'>
                <p>Hello,</p>
                <p>You have requested to change your email address in SecureAuth.</p>

                <div class='warning'>
                    <strong>Security Notice:</strong><br>
                    This verification code is sent to your <strong>current email address</strong> to confirm you have access to it.
                </div>

                <p><strong>Your verification code:</strong></p>
                <div class='otp-code'>{$current_email_otp}</div>

                <p>This code will expire in 10 minutes.</p>
                <p>If you did not request this change, please ignore this email and contact support immediately.</p>

                <p>Best regards,<br>SecureAuth Team</p>
            </div>
        </div>
    </body>
    </html>
    ";

    $mail = new PHPMailer\PHPMailer\PHPMailer(true);
    $mail->isSMTP();
    $mail->Host = SMTP_HOST;
    $mail->SMTPAuth = true;
    $mail->Username = SMTP_USERNAME;
    $mail->Password = SMTP_PASSWORD;
    $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
    $mail->Port = SMTP_PORT;

    $mail->setFrom(FROM_EMAIL, FROM_NAME);
    $mail->addAddress($current_email);

    $mail->isHTML(true);
    $mail->Subject = $subject;
    $mail->Body = $message;
    $mail->AltBody = strip_tags(str_replace(['<br>', '</p>'], ["\n", "\n\n"], $message));

    $current_email_sent = false;
    try {
        $mail->send();
        $current_email_sent = true;
    } catch (Exception $e) {
        error_log('Current email OTP failed: ' . $e->getMessage());
    }

    // Send OTP to new email
    $subject = 'Email Change Verification - New Email';
    $message = "
    <html>
    <head>
        <title>Email Change Verification</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #28a745 0%, #20c997 100%); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 20px; border-radius: 0 0 10px 10px; }
            .otp-code { background: #fff; border: 2px solid #28a745; padding: 15px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 5px; margin: 20px 0; }
            .info { background: #d1ecf1; border: 1px solid #bee5eb; padding: 15px; border-radius: 5px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <div class='container'>
            <div class='header'>
                <h2>✅ New Email Verification</h2>
            </div>
            <div class='content'>
                <p>Hello,</p>
                <p>This email address has been requested as a new email for a SecureAuth account.</p>

                <div class='info'>
                    <strong>Verification Required:</strong><br>
                    Please verify this email address by entering the code below when prompted.
                </div>

                <p><strong>Your verification code:</strong></p>
                <div class='otp-code'>{$new_email_otp}</div>

                <p>This code will expire in 10 minutes.</p>
                <p>If you did not request this change, please ignore this email.</p>

                <p>Best regards,<br>SecureAuth Team</p>
            </div>
        </div>
    </body>
    </html>
    ";

    $mail->clearAddresses();
    $mail->addAddress($new_email);
    $mail->Subject = $subject;
    $mail->Body = $message;
    $mail->AltBody = strip_tags(str_replace(['<br>', '</p>'], ["\n", "\n\n"], $message));

    $new_email_sent = false;
    try {
        $mail->send();
        $new_email_sent = true;
    } catch (Exception $e) {
        error_log('New email OTP failed: ' . $e->getMessage());
    }

    if ($current_email_sent && $new_email_sent) {
        logActivity($pdo, $user_id, 'Email change initiated', "New email: $new_email");
        echo json_encode([
            'success' => true,
            'message' => 'OTP codes sent to both email addresses.',
            'otp_data' => [
                'expires' => $otp_expires
            ]
        ]);
    } elseif ($current_email_sent) {
        echo json_encode(['success' => false, 'message' => 'OTP sent to current email, but failed to send to new email address.']);
    } elseif ($new_email_sent) {
        echo json_encode(['success' => false, 'message' => 'OTP sent to new email, but failed to send to current email address.']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Failed to send OTP codes to both email addresses.']);
    }

} catch (PDOException $e) {
    error_log('Email change OTP error: ' . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'An error occurred while processing your request.']);
}
?>