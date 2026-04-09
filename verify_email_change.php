<?php
session_start();
require_once 'db.php';
require_once 'csrf.php';

header('Content-Type: application/json');

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    echo json_encode(['success' => false, 'message' => 'Please log in to verify email change.']);
    exit;
}

$user_id = $_SESSION['user_id'];

// Get current email for logging
$stmt = $pdo->prepare("SELECT email FROM users WHERE id = ?");
$stmt->execute([$user_id]);
$user_data = $stmt->fetch(PDO::FETCH_ASSOC);
$old_email = $user_data['email'];

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
$current_email_otp = trim($input['current_email_otp'] ?? '');
$new_email_otp = trim($input['new_email_otp'] ?? '');

// Pad OTPs to 6 digits with leading zeros
$current_email_otp = str_pad($current_email_otp, 6, '0', STR_PAD_LEFT);
$new_email_otp = str_pad($new_email_otp, 6, '0', STR_PAD_LEFT);

// Validate inputs
if (empty($new_email) || empty($current_email_otp) || empty($new_email_otp)) {
    echo json_encode(['success' => false, 'message' => 'All fields are required.']);
    exit;
}

// Validate OTP format
if (!preg_match('/^[0-9]{6}$/', $current_email_otp) || !preg_match('/^[0-9]{6}$/', $new_email_otp)) {
    echo json_encode(['success' => false, 'message' => 'Please enter valid 6-digit OTP codes.']);
    exit;
}

// Check if OTP session data exists
if (!isset($_SESSION['email_change_otp'])) {
    echo json_encode(['success' => false, 'message' => 'No email change verification in progress. Please start the email change process again.']);
    exit;
}

$otp_data = $_SESSION['email_change_otp'];

// Check if OTP has expired
$current_time = date('Y-m-d H:i:s');
if ($current_time > $otp_data['expires']) {
    unset($_SESSION['email_change_otp']);
    echo json_encode(['success' => false, 'message' => 'OTP codes have expired. Please request new codes.']);
    exit;
}

// Verify OTP codes
if ($current_email_otp !== $otp_data['current_email_otp']) {
    echo json_encode(['success' => false, 'message' => 'Invalid OTP code from current email.']);
    exit;
}

if ($new_email_otp !== $otp_data['new_email_otp']) {
    echo json_encode(['success' => false, 'message' => 'Invalid OTP code from new email.']);
    exit;
}

// Verify new email matches
if ($new_email !== $otp_data['new_email']) {
    echo json_encode(['success' => false, 'message' => 'Email address mismatch. Please try again.']);
    exit;
}

try {
    // Check if new email is still available (in case it was taken while user was verifying)
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ? AND id != ?");
    $stmt->execute([$new_email, $user_id]);
    if ($stmt->fetch()) {
        unset($_SESSION['email_change_otp']);
        echo json_encode(['success' => false, 'message' => 'This email address is no longer available.']);
        exit;
    }

    // Update email in database
    $stmt = $pdo->prepare("UPDATE users SET email = ? WHERE id = ?");
    $stmt->execute([$new_email, $user_id]);

    if ($stmt->rowCount() > 0) {
        // Clear OTP session data
        unset($_SESSION['email_change_otp']);

        logActivity($pdo, $user_id, 'Email changed', "From: $old_email To: $new_email");

        // Update session email if it exists
        if (isset($_SESSION['user'])) {
            // Get updated user data to update session
            $stmt = $pdo->prepare("SELECT username FROM users WHERE id = ?");
            $stmt->execute([$user_id]);
            $updated_user = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($updated_user) {
                $_SESSION['user'] = $updated_user['username'];
            }
        }

        echo json_encode([
            'success' => true,
            'message' => 'Email address updated successfully!'
        ]);
    } else {
        echo json_encode(['success' => false, 'message' => 'Failed to update email address.']);
    }

} catch (PDOException $e) {
    error_log('Email change verification error: ' . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'An error occurred while updating your email.']);
}
?>