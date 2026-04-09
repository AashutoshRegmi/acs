<?php
// OTP verification script with improved UI

include 'db.php';
require_once 'turnstile.php';

$message = '';
$messageType = '';
$showLoginButton = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = sanitize($_POST['email']);
    $otp = sanitize($_POST['otp']);
    $cfTurnstileResponse = $_POST['cf-turnstile-response'] ?? '';
    $maxOtpAttempts = 5;
    $otpCooldownMinutes = 2;

    if (!verifyTurnstileToken($cfTurnstileResponse)) {
        $message = 'CAPTCHA verification failed. Please try again.';
        $messageType = 'danger';
    } else {

    // Validate OTP format
    if (!preg_match('/^[0-9]{6}$/', $otp)) {
        $message = 'Invalid OTP format. Please enter a 6-digit code.';
        $messageType = 'danger';
    } else {
        try {
            // Check if user exists and OTP is valid
            $stmt = $pdo->prepare("SELECT id, username, otp, otp_expires, otp_failed_attempts, otp_cooldown_until FROM users WHERE email = ? AND verified = FALSE");
            $stmt->execute([$email]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$user) {
                $message = 'Account not found or already verified.';
                $messageType = 'warning';
            } else {
                // Check if OTP matches and hasn't expired
                $currentTime = date('Y-m-d H:i:s');
                $cooldownUntil = $user['otp_cooldown_until'] ?? null;

                if (!empty($cooldownUntil) && strtotime($cooldownUntil) > time()) {
                    $remainingSeconds = strtotime($cooldownUntil) - time();
                    $minutes = (int) floor($remainingSeconds / 60);
                    $seconds = $remainingSeconds % 60;
                    $message = sprintf('Too many incorrect OTP attempts. Please wait %d:%02d before trying again.', $minutes, $seconds);
                    $messageType = 'warning';
                } elseif ($user['otp'] === $otp && $currentTime <= $user['otp_expires']) {
                    // Verify the account
                    $stmt = $pdo->prepare("UPDATE users SET verified = TRUE, otp = NULL, otp_expires = NULL, otp_failed_attempts = 0, otp_cooldown_until = NULL WHERE id = ?");
                    $stmt->execute([$user['id']]);

                    // Start session and redirect to dashboard
                    session_start();
                    session_regenerate_id(true);
                    $_SESSION['user'] = $user['username'];
                    $_SESSION['user_id'] = $user['id'];
                    header('Location: dashboard.html');
                    exit;
                } elseif ($user['otp'] === $otp && $currentTime > $user['otp_expires']) {
                    $message = 'OTP has expired. Please request a new verification code.';
                    $messageType = 'warning';
                } else {
                    $failedAttempts = ((int)($user['otp_failed_attempts'] ?? 0)) + 1;

                    if ($failedAttempts >= $maxOtpAttempts) {
                        $cooldownUntil = date('Y-m-d H:i:s', strtotime('+' . $otpCooldownMinutes . ' minutes'));
                        $stmt = $pdo->prepare("UPDATE users SET otp_failed_attempts = 0, otp_cooldown_until = ? WHERE id = ?");
                        $stmt->execute([$cooldownUntil, $user['id']]);

                        $message = 'Too many incorrect OTP attempts. Please wait 2 minutes before trying again.';
                        $messageType = 'warning';
                    } else {
                        $stmt = $pdo->prepare("UPDATE users SET otp_failed_attempts = ?, otp_cooldown_until = NULL WHERE id = ?");
                        $stmt->execute([$failedAttempts, $user['id']]);

                        $remainingAttempts = $maxOtpAttempts - $failedAttempts;
                        $message = 'Invalid OTP. Please check your code and try again. Remaining attempts: ' . $remainingAttempts . '.';
                        $messageType = 'danger';
                    }
                }
            }
        } catch (PDOException $e) {
            $message = 'Database error: ' . $e->getMessage();
            $messageType = 'danger';
        }
    }
    }
} else {
    $message = 'Invalid request method.';
    $messageType = 'danger';
}

// Sanitize input function
function sanitize($data) {
    return htmlspecialchars(stripslashes(trim($data)));
}
?>

<?php
session_start();
$pendingEmail = isset($_SESSION['pending_verification']) ? $_SESSION['pending_verification'] : '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verification Result - SecureAuth</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="glass-card">
                    <div class="card-body p-5">
                        <h2 class="text-center mb-4">Verification Result</h2>

                        <?php if ($message): ?>
                            <div class="alert alert-<?php echo $messageType; ?> text-center mb-4" role="alert">
                                <?php if ($messageType === 'success'): ?>
                                    <i class="fas fa-check-circle me-2"></i>
                                <?php elseif ($messageType === 'danger'): ?>
                                    <i class="fas fa-exclamation-triangle me-2"></i>
                                <?php elseif ($messageType === 'warning'): ?>
                                    <i class="fas fa-exclamation-circle me-2"></i>
                                <?php endif; ?>
                                <?php echo $message; ?>
                            </div>
                        <?php endif; ?>

                        <div class="text-center">
                            <?php if ($showLoginButton): ?>
                                <a href="login.html" class="btn btn-primary btn-lg me-2">
                                    <i class="fas fa-sign-in-alt me-2"></i>Login Now
                                </a>
                            <?php endif; ?>

                            <a href="verify_otp_form.php" class="btn btn-outline-primary btn-lg me-2">
                                <i class="fas fa-arrow-left me-2"></i>Try Again
                            </a>

                            <a href="register.html" class="btn btn-outline-secondary btn-lg">
                                <i class="fas fa-user-plus me-2"></i>Register
                            </a>
                        </div>

                        <div class="text-center mt-4">
                            <a href="index.html" class="text-decoration-none">
                                <i class="fas fa-home me-1"></i>Back to Home
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>