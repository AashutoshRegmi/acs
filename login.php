<?php
// Login script with optional Google Authenticator 2FA

session_start();

include 'db.php';
require_once 'csrf.php';
require_once 'turnstile.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_validate_request()) {
        echo json_encode(['success' => false, 'message' => 'Invalid security token. Please refresh and try again.']);
        exit;
    }

    $username = htmlspecialchars(stripslashes(trim($_POST['username'])));
    $password = $_POST['password'];
    $cfTurnstileResponse = $_POST['cf-turnstile-response'] ?? '';

    if (!verifyTurnstileToken($cfTurnstileResponse)) {
        echo json_encode(['success' => false, 'message' => 'CAPTCHA verification failed. Please try again.']);
        exit;
    }

    try {
        // Check if this is a username or email
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? OR email = ?");
        $stmt->execute([$username, $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            if ($user['verified']) {
                // Check if account is locked
                if ($user['locked_until'] && strtotime($user['locked_until']) > time()) {
                    echo json_encode(['success' => false, 'message' => 'Account is temporarily locked due to too many failed attempts.']);
                    exit;
                }

                // Check if password needs to be changed (30 days)
                if ($user['password_changed_at'] && strtotime($user['password_changed_at']) < strtotime('-30 days')) {
                    echo json_encode([
                        'success' => false,
                        'message' => 'Your password has expired. Please change your password to continue.',
                        'requires_password_change' => true
                    ]);
                    exit;
                }

                // Check if 2FA is enabled
                if ($user['twofa_enabled']) {
                    // Store user info temporarily and redirect to 2FA verification
                    $_SESSION['pending_2fa_user_id'] = $user['id'];
                    $_SESSION['pending_2fa_username'] = $user['username'];

                    echo json_encode([
                        'success' => true,
                        'requires_2fa' => true,
                        'message' => 'Credentials verified. Please enter your 2FA code.'
                    ]);
                    exit;
                } else {
                    // No 2FA required, complete login
                    session_regenerate_id(true);
                    $_SESSION['user'] = $user['username'];
                    $_SESSION['user_id'] = $user['id'];

                    // Reset login attempts on successful login
                    $stmt = $pdo->prepare("UPDATE users SET login_attempts = 0, locked_until = NULL WHERE id = ?");
                    $stmt->execute([$user['id']]);

                    logActivity($pdo, $user['id'], 'Login successful');

                    echo json_encode(['success' => true, 'message' => 'Login successful! Welcome back.']);
                    exit;
                }

            } else {
                echo json_encode(['success' => false, 'message' => 'Account not verified. Please check your email for the verification code.']);
                exit;
            }
        } else {
            // Handle failed login attempt
            if ($user) {
                $new_attempts = $user['login_attempts'] + 1;
                $locked_until = null;

                if ($new_attempts >= 5) {
                    $locked_until = date('Y-m-d H:i:s', strtotime('+15 minutes'));
                }

                $stmt = $pdo->prepare("UPDATE users SET login_attempts = ?, locked_until = ? WHERE id = ?");
                $stmt->execute([$new_attempts, $locked_until, $user['id']]);

                logActivity($pdo, $user['id'], 'Failed login attempt');
            }

            echo json_encode(['success' => false, 'message' => 'Invalid username or password.']);
            exit;
        }
    } catch (PDOException $e) {
        error_log('Login error: ' . $e->getMessage());
        echo json_encode(['success' => false, 'message' => 'An error occurred during login. Please try again.']);
        exit;
    }
} else {
    echo json_encode(['success' => false, 'message' => 'Invalid request method.']);
    exit;
}

function sanitize($data) {
    return htmlspecialchars(stripslashes(trim($data)));
}
?>