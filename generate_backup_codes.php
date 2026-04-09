<?php
session_start();
require_once 'db.php';
require_once 'csrf.php';

header('Content-Type: application/json');

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    echo json_encode(['success' => false, 'message' => 'Please log in to access this feature.']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !csrf_validate_request()) {
    echo json_encode(['success' => false, 'message' => 'Security validation failed. Please refresh and try again.']);
    exit;
}

$user_id = $_SESSION['user_id'];

try {
    // Check if 2FA is enabled for this user
    $stmt = $pdo->prepare("SELECT twofa_enabled FROM users WHERE id = ?");
    $stmt->execute([$user_id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user['twofa_enabled']) {
        echo json_encode(['success' => false, 'message' => 'Two-Factor Authentication must be enabled first.']);
        exit;
    }

    // Delete any existing backup codes for this user
    $stmt = $pdo->prepare("DELETE FROM twofa_backup_codes WHERE user_id = ?");
    $stmt->execute([$user_id]);

    // Generate 10 backup codes using cryptographically secure randomness.
    $backup_codes = [];
    for ($i = 0; $i < 10; $i++) {
        $inserted = false;
        $attempts = 0;

        while (!$inserted && $attempts < 10) {
            $attempts++;
            $code = strtoupper(bin2hex(random_bytes(4)));

            try {
                $stmt = $pdo->prepare("INSERT INTO twofa_backup_codes (user_id, code) VALUES (?, ?)");
                $stmt->execute([$user_id, $code]);
                $backup_codes[] = $code;
                $inserted = true;
            } catch (PDOException $e) {
                // Retry only on rare per-user code collisions.
                if ((int)$e->getCode() !== 23000) {
                    throw $e;
                }
            }
        }

        if (!$inserted) {
            throw new RuntimeException('Unable to generate a unique backup code.');
        }
    }

    echo json_encode([
        'success' => true,
        'backup_codes' => $backup_codes,
        'message' => 'Backup codes generated successfully!'
    ]);

} catch (Exception $e) {
    error_log('Backup codes generation error: ' . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'An error occurred while generating backup codes.']);
}
?>