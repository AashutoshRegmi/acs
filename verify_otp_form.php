<?php
session_start();
$pendingEmail = isset($_SESSION['pending_verification']) ? $_SESSION['pending_verification'] : '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Account - SecureAuth</title>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit" async defer></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="glass-card">
                    <div class="card-body p-5">
                        <h2 class="text-center mb-4">
                            <i class="fas fa-shield-alt me-2"></i>Verify Your Account
                        </h2>
                        <div class="alert alert-info mb-4">
                            <strong>How to verify:</strong>
                            <ol class="mb-0 mt-2">
                                <li>Check your email for the 6-digit verification code</li>
                                <li>Enter your email address and the code below</li>
                                <li>Click "Verify Account" to activate your account</li>
                            </ol>
                        </div>
                        <p class="text-center text-muted mb-4">
                            Enter the 6-digit verification code sent to your email
                        </p>

                        <form id="verifyForm" action="verify_otp.php" method="POST">
                            <div class="mb-3">
                                <label for="email" class="form-label">
                                    <i class="fas fa-envelope me-2"></i>Email Address
                                </label>
                                <input type="email" class="form-control" id="email" name="email"
                                       value="<?php echo htmlspecialchars($pendingEmail); ?>" required>
                            </div>

                            <div class="mb-3">
                                <label for="otp" class="form-label">
                                    <i class="fas fa-key me-2"></i>Verification Code
                                </label>
                                <input type="text" class="form-control text-center" id="otp" name="otp"
                                       maxlength="6" pattern="[0-9]{6}" required
                                       placeholder="000000" style="font-size: 1.5rem; letter-spacing: 0.5rem;">
                            </div>

                            <div class="mb-3">
                                <div class="cf-turnstile" id="turnstileWidget"></div>
                            </div>

                            <button type="submit" class="btn btn-primary w-100 mb-3">
                                <i class="fas fa-check-circle me-2"></i>Verify Account
                            </button>
                        </form>

                        <div class="text-center">
                            <p class="mb-2">Didn't receive the code?</p>
                            <button id="resendBtn" class="btn btn-outline-secondary">
                                <i class="fas fa-redo me-2"></i>Resend Code
                            </button>
                        </div>

                        <div class="text-center mt-3">
                            <a href="login.html" class="text-decoration-none">
                                <i class="fas fa-sign-in-alt me-1"></i>Back to Login
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="csrf_client.js"></script>
    <script>
        // Auto-focus on OTP input
        document.getElementById('otp').focus();

        if (window.ensureCsrfToken) {
            window.ensureCsrfToken().catch(() => {});
        }

        // Format OTP input
        document.getElementById('otp').addEventListener('input', function(e) {
            // Remove non-numeric characters
            this.value = this.value.replace(/[^0-9]/g, '');

        });

        document.getElementById('verifyForm').addEventListener('submit', function(e) {
            const formData = new FormData(this);
            if (!formData.get('cf-turnstile-response')) {
                e.preventDefault();
                alert('Please complete CAPTCHA verification first.');
            }
        });

        // Resend code functionality
        document.getElementById('resendBtn').addEventListener('click', function() {
            const email = document.getElementById('email').value;
            if (!email) {
                alert('Please enter your email address first');
                return;
            }

            this.disabled = true;
            this.textContent = 'Sending...';

            const tokenInput = document.querySelector('[name="cf-turnstile-response"]');
            if (!tokenInput || !tokenInput.value) {
                alert('Please complete CAPTCHA verification first.');
                this.disabled = false;
                this.textContent = 'Resend Code';
                return;
            }

            fetch('resend_otp.php', {
                method: 'POST',
                headers: window.withCsrfHeaders ? window.withCsrfHeaders() : {},
                body: new URLSearchParams({
                    email: email,
                    'cf-turnstile-response': tokenInput.value
                })
            })
            .then(response => response.text())
            .then(data => {
                alert(data);
                this.disabled = false;
                this.textContent = 'Resend Code';
            })
            .catch(error => {
                alert('Error sending code. Please try again.');
                this.disabled = false;
                this.textContent = 'Resend Code';
            });
        });

        document.addEventListener('DOMContentLoaded', function () {
            function renderWidgetWithRetry(siteKey, remainingAttempts) {
                const widget = document.getElementById('turnstileWidget');
                if (!widget) {
                    return;
                }

                if (window.turnstile && typeof window.turnstile.render === 'function') {
                    widget.innerHTML = '';
                    window.turnstile.render(widget, {
                        sitekey: siteKey
                    });
                    return;
                }

                if (remainingAttempts <= 0) {
                    return;
                }

                setTimeout(function () {
                    renderWidgetWithRetry(siteKey, remainingAttempts - 1);
                }, 150);
            }

            fetch('public_config.php')
                .then(response => response.json())
                .then(config => {
                    if (!config.turnstileSiteKey) {
                        return;
                    }

                    renderWidgetWithRetry(config.turnstileSiteKey, 40);
                })
                .catch(() => {});
        });
    </script>
</body>
</html>