<?php
// Secure registration script with email verification

// Include PHPMailer classes
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require 'vendor/autoload.php';
include 'db.php';
include 'email_config.php';
require_once 'csrf.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Function to sanitize input
function sanitize($data) {
    return htmlspecialchars(stripslashes(trim($data)));
}

// Function to check password strength
function checkPasswordStrength($password) {
    $errors = [];
    if (strlen($password) < 8) $errors[] = 'Password must be at least 8 characters';
    if (!preg_match('/[a-z]/', $password)) $errors[] = 'Password must contain a lowercase letter';
    if (!preg_match('/[A-Z]/', $password)) $errors[] = 'Password must contain an uppercase letter';
    if (!preg_match('/\d/', $password)) $errors[] = 'Password must contain a number';
    if (!preg_match('/[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]/', $password)) $errors[] = 'Password must contain a special character';
    return $errors;
}

// Function to verify Turnstile
function verifyTurnstile($token) {
    $secret = env('TURNSTILE_SECRET_KEY', '');
    if ($secret === '') {
        return false;
    }

    $url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
    $data = [
        'secret' => $secret,
        'response' => $token
    ];

    $options = [
        'http' => [
            'header' => "Content-type: application/x-www-form-urlencoded\r\n",
            'method' => 'POST',
            'content' => http_build_query($data)
        ]
    ];
    $context = stream_context_create($options);
    $result = file_get_contents($url, false, $context);
    $response = json_decode($result, true);
    return $response['success'] ?? false;
}

// Function to send verification email using Gmail SMTP with PHPMailer
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

// Handle POST request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_validate_request()) {
        echo json_encode(['status' => 'error', 'message' => 'Invalid security token. Please refresh and try again.']);
        exit;
    }

    $email = sanitize($_POST['email']);
    $username = sanitize($_POST['username']);
    $firstName = sanitize($_POST['firstName']);
    $middleName = !empty($_POST['middleName']) ? sanitize($_POST['middleName']) : null;
    $lastName = sanitize($_POST['lastName']);
    $countryCode = sanitize($_POST['countryCode']);
    $phoneNumber = sanitize($_POST['phoneNumber']);
    $password = $_POST['password'];
    $cfTurnstileResponse = $_POST['cf-turnstile-response'] ?? '';

    // Basic validation
    if (empty($email) || empty($username) || empty($firstName) || empty($lastName) || empty($countryCode) || empty($phoneNumber) || empty($password)) {
        echo json_encode(['status' => 'error', 'message' => 'All required fields are required']);
        exit;
    }

    // Validate email
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo json_encode(['status' => 'error', 'message' => 'Invalid email format']);
        exit;
    }

    // Validate phone number (basic check)
    if (!preg_match('/^[0-9+\-\s()]+$/', $countryCode . $phoneNumber)) {
        echo json_encode(['status' => 'error', 'message' => 'Invalid phone number format']);
        exit;
    }

    // Check password strength
    $strengthErrors = checkPasswordStrength($password);
    if (!empty($strengthErrors)) {
        echo json_encode(['status' => 'error', 'message' => 'Password does not meet requirements: ' . implode(', ', $strengthErrors)]);
        exit;
    }

    // Verify Turnstile
    if (!verifyTurnstile($cfTurnstileResponse)) {
        echo json_encode(['status' => 'error', 'message' => 'CAPTCHA verification failed. Please try again.']);
        exit;
    }

    // Generate 6-digit OTP and expiration time (10 minutes from now)
    try {
        $otp = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    } catch (Throwable $e) {
        error_log('Secure OTP generation failed: ' . $e->getMessage());
        echo json_encode(['status' => 'error', 'message' => 'Unable to generate verification code. Please try again.']);
        exit;
    }
    $otpExpires = date('Y-m-d H:i:s', strtotime('+10 minutes'));

    // Hash password
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    try {
        // Check if username or email exists
        $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
        $stmt->execute([$username, $email]);
        if ($stmt->rowCount() > 0) {
            echo json_encode(['status' => 'error', 'message' => 'Username or email already exists']);
            exit;
        }

        // Insert user
        $stmt = $pdo->prepare("INSERT INTO users (email, username, first_name, middle_name, last_name, country_code, phone_number, password, otp, otp_expires) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->execute([$email, $username, $firstName, $middleName, $lastName, $countryCode, $phoneNumber, $hashedPassword, $otp, $otpExpires]);

        // Send verification email with OTP
        if (sendVerificationEmail($email, $otp)) {
            // Store email in session for OTP verification page
            $_SESSION['pending_verification'] = $email;

            // Return success with redirect
            echo json_encode(['status' => 'success', 'redirect' => 'verify_otp_form.php']);
        } else {
            echo json_encode(['status' => 'error', 'message' => 'Registration successful, but email could not be sent. Contact admin.']);
        }
    } catch (PDOException $e) {
        echo json_encode(['status' => 'error', 'message' => 'Database error: ' . $e->getMessage()]);
    }
} else {
    echo json_encode(['status' => 'error', 'message' => 'Invalid request']);
}
?>