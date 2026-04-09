<?php
session_start();
require_once 'db.php';
require_once 'email_config.php';
require_once 'csrf.php';

header('Content-Type: application/json');

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    echo json_encode(['success' => false, 'message' => 'Please log in to edit your profile.']);
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
$first_name = trim($_POST['first_name'] ?? '');
$middle_name = trim($_POST['middle_name'] ?? '');
$last_name = trim($_POST['last_name'] ?? '');
$country_code = trim($_POST['country_code'] ?? '');
$phone_number = trim($_POST['phone_number'] ?? '');
$email = trim($_POST['email'] ?? '');
$cf_turnstile_response = $_POST['cf-turnstile-response'] ?? '';

// Validate CAPTCHA
if (empty($cf_turnstile_response)) {
    echo json_encode(['success' => false, 'message' => 'Please complete the security verification.']);
    exit;
}

// Verify CAPTCHA with Cloudflare
$turnstile_secret = env('TURNSTILE_SECRET_KEY', '');
$verify_url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

if ($turnstile_secret === '') {
    echo json_encode(['success' => false, 'message' => 'Security verification is not configured. Contact support.']);
    exit;
}

$ch = curl_init($verify_url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
    'secret' => $turnstile_secret,
    'response' => $cf_turnstile_response,
    'remoteip' => $_SERVER['REMOTE_ADDR']
]));
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

$turnstile_response = curl_exec($ch);
curl_close($ch);

$turnstile_data = json_decode($turnstile_response, true);

if (!$turnstile_data['success']) {
    echo json_encode(['success' => false, 'message' => 'Security verification failed. Please try again.']);
    exit;
}

// Get current user email to check if it's being changed
$stmt = $pdo->prepare("SELECT email FROM users WHERE id = ?");
$stmt->execute([$user_id]);
$current_user = $stmt->fetch(PDO::FETCH_ASSOC);
$current_email = $current_user['email'];
$email_changed = $email !== $current_email;

// If email is being changed, it should have been verified through OTP first
// So we don't update email here - it's handled separately
if ($email_changed) {
    echo json_encode(['success' => false, 'message' => 'Email changes require OTP verification. Please complete the email change process first.']);
    exit;
}

// Validate name formats
if (!preg_match('/^[A-Za-z\s]{2,50}$/', $first_name)) {
    echo json_encode(['success' => false, 'message' => 'First name must be 2-50 characters and contain only letters.']);
    exit;
}

if (!empty($middle_name) && !preg_match('/^[A-Za-z\s]{1,50}$/', $middle_name)) {
    echo json_encode(['success' => false, 'message' => 'Middle name must contain only letters.']);
    exit;
}

if (!preg_match('/^[A-Za-z\s]{2,50}$/', $last_name)) {
    echo json_encode(['success' => false, 'message' => 'Last name must be 2-50 characters and contain only letters.']);
    exit;
}

// Validate phone number
if (!preg_match('/^[0-9]{7,15}$/', $phone_number)) {
    echo json_encode(['success' => false, 'message' => 'Phone number must be 7-15 digits.']);
    exit;
}

// Validate country code
$valid_country_codes = [
    '+1', '+44', '+91', '+86', '+81', '+49', '+33', '+39', '+34', '+55',
    '+61', '+7', '+82', '+65', '+971', '+966', '+20', '+27', '+234', '+254',
    '+255', '+256', '+257', '+258', '+260', '+261', '+263', '+264', '+265',
    '+266', '+267', '+268', '+269', '+290', '+291', '+297', '+298', '+299',
    '+350', '+351', '+352', '+353', '+354', '+355', '+356', '+357', '+358',
    '+359', '+370', '+371', '+372', '+373', '+374', '+375', '+376', '+377',
    '+378', '+380', '+381', '+382', '+383', '+385', '+386', '+387', '+389',
    '+420', '+421', '+423', '+500', '+501', '+502', '+503', '+504', '+505',
    '+506', '+507', '+508', '+509', '+590', '+591', '+592', '+593', '+594',
    '+595', '+596', '+597', '+598', '+599', '+670', '+672', '+673', '+674',
    '+675', '+676', '+677', '+678', '+679', '+680', '+681', '+682', '+683',
    '+684', '+685', '+686', '+687', '+688', '+689', '+690', '+691', '+692',
    '+850', '+852', '+853', '+855', '+856', '+880', '+886', '+960', '+961',
    '+962', '+963', '+964', '+965', '+966', '+967', '+968', '+970', '+971',
    '+972', '+973', '+974', '+975', '+976', '+977', '+992', '+993', '+994',
    '+995', '+996', '+998'
];

if (!in_array($country_code, $valid_country_codes)) {
    echo json_encode(['success' => false, 'message' => 'Please select a valid country code.']);
    exit;
}

try {
    // Update user profile
    $stmt = $pdo->prepare("
        UPDATE users
        SET first_name = ?, middle_name = ?, last_name = ?, country_code = ?, phone_number = ?
        WHERE id = ?
    ");

    $stmt->execute([
        $first_name,
        $middle_name ?: null, // Allow empty middle name
        $last_name,
        $country_code,
        $phone_number,
        $user_id
    ]);

    if ($stmt->rowCount() > 0) {
        // Send confirmation email
        $stmt = $pdo->prepare("SELECT email FROM users WHERE id = ?");
        $stmt->execute([$user_id]);
        $user_email = $stmt->fetchColumn();

        $subject = 'Profile Updated Successfully';
        $message = "
        <html>
        <head>
            <title>Profile Updated</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: linear-gradient(135deg, #28a745 0%, #20c997 100%); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }
                .content { background: #f9f9f9; padding: 20px; border-radius: 0 0 10px 10px; }
                .info { background: #e9ecef; padding: 15px; border-radius: 5px; margin: 20px 0; }
            </style>
        </head>
        <body>
            <div class='container'>
                <div class='header'>
                    <h2>✅ Profile Updated</h2>
                </div>
                <div class='content'>
                    <p>Hello,</p>
                    <p>Your profile has been successfully updated in SecureAuth.</p>

                    <div class='info'>
                        <strong>Updated Information:</strong><br>
                        Name: {$first_name} " . (!empty($middle_name) ? $middle_name . ' ' : '') . "{$last_name}<br>
                        Phone: {$country_code} {$phone_number}<br>
                        Updated: " . date('Y-m-d H:i:s') . "<br>
                        IP Address: " . $_SERVER['REMOTE_ADDR'] . "
                    </div>

                    <p>If you did not make this change, please contact our support team immediately.</p>

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
        $mail->addAddress($user_email);

        $mail->isHTML(true);
        $mail->Subject = $subject;
        $mail->Body = $message;
        $mail->AltBody = strip_tags(str_replace(['<br>', '</p>'], ["\n", "\n\n"], $message));

        try {
            $mail->send();
        } catch (Exception $e) {
            // Log email error but don't fail the profile update
            error_log('Profile update email failed: ' . $e->getMessage());
        }

        echo json_encode(['success' => true, 'message' => 'Profile updated successfully!']);
    } else {
        echo json_encode(['success' => false, 'message' => 'No changes were made to your profile.']);
    }

} catch (PDOException $e) {
    error_log('Profile update error: ' . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'An error occurred while updating your profile. Please try again.']);
}
?>