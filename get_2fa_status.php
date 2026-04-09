<?php
session_start();
require_once 'db.php';

header('Content-Type: application/json');

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    echo json_encode(['success' => false, 'message' => 'Please log in to access this feature.']);
    exit;
}

$user_id = $_SESSION['user_id'];

try {
    $stmt = $pdo->prepare("SELECT twofa_enabled FROM users WHERE id = ?");
    $stmt->execute([$user_id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    echo json_encode([
        'success' => true,
        'enabled' => (bool)$user['twofa_enabled']
    ]);

} catch (Exception $e) {
    error_log('Get 2FA status error: ' . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'An error occurred while checking 2FA status.']);
}
?>