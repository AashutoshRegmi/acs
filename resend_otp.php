<?php
// Resend OTP script

// Include PHPMailer classes
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require 'vendor/autoload.php';
include 'db.php';
include 'email_config.php';
require_once 'csrf.php';
require_once 'turnstile.php';

// Function to send verification email with OTP
function sendVerificationEmail($email, $otp) {
    $mail = new PHPMailer(true);

    try {
        // Server settings
        $mail->isSMTP();
        $mail->Host = SMTP_HOST;
        $mail->SMTPAuth = true;
        $mail->Username = SMTP_USERNAME;
        $mail->Password = SMTP_PASSWORD;
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = SMTP_PORT;

        // Recipients
        $mail->setFrom(FROM_EMAIL, FROM_NAME);
        $mail->addAddress($email);

        // Content
        $mail->isHTML(true);
        $mail->Subject = 'Your Account Verification Code - SecureAuth';

        $mail->Body = "
        <html>
        <head>
            <title>Account Verification</title>
            <style>
                .otp-code {
                    font-size: 24px;
                    font-weight: bold;
                    color: #3b82f6;
                    background-color: #f3f4f6;
                    padding: 10px 20px;
                    border-radius: 5px;
                    display: inline-block;
                    margin: 10px 0;
                    font-family: monospace;
                }
            </style>
        </head>
        <body>
            <h2>Welcome to SecureAuth!</h2>
            <p>Thank you for registering. Please use the verification code below to activate your account:</p>
            <div class='otp-code'>$otp</div>
            <p><strong>Important:</strong> This code will expire in 10 minutes for security reasons.</p>
            <p>If you didn't create this account, please ignore this email.</p>
            <br>
            <p>Best regards,<br>SecureAuth Team</p>
        </body>
        </html>
        ";

        $mail->AltBody = "Welcome to SecureAuth!\n\nThank you for registering. Your verification code is: $otp\n\nThis code will expire in 10 minutes.\n\nIf you didn't create this account, please ignore this email.\n\nBest regards,\nSecureAuth Team";

        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log("Email sending failed: " . $mail->ErrorInfo);
        return false;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_validate_request()) {
        echo 'Invalid security token. Please refresh and try again.';
        exit;
    }

    $cfTurnstileResponse = $_POST['cf-turnstile-response'] ?? '';
    if (!verifyTurnstileToken($cfTurnstileResponse)) {
        echo 'CAPTCHA verification failed. Please try again.';
        exit;
    }

    $email = sanitize($_POST['email']);

    try {
        // Check if user exists and is not verified
        $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ? AND verified = FALSE");
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            echo 'Account not found or already verified.';
            exit;
        }

        // Generate new OTP and expiration
        $otp = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        $otpExpires = date('Y-m-d H:i:s', strtotime('+10 minutes'));

        // Update user with new OTP
        $stmt = $pdo->prepare("UPDATE users SET otp = ?, otp_expires = ?, otp_failed_attempts = 0, otp_cooldown_until = NULL WHERE id = ?");
        $stmt->execute([$otp, $otpExpires, $user['id']]);

        // Send new verification email
        if (sendVerificationEmail($email, $otp)) {
            echo 'New verification code sent to your email.';
        } else {
            echo 'Failed to send verification code. Please try again.';
        }
    } catch (PDOException $e) {
        echo 'Database error: ' . $e->getMessage();
    }
} else {
    echo 'Invalid request method.';
}

// Sanitize input function
function sanitize($data) {
    return htmlspecialchars(stripslashes(trim($data)));
}
?>