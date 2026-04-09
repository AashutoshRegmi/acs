<?php
// Get user data for dashboard
session_start();

header('Content-Type: application/json');

if (!isset($_SESSION['user'])) {
    echo json_encode(['success' => false, 'message' => 'Not authenticated']);
    exit;
}

include 'db.php';

try {
    $stmt = $pdo->prepare("SELECT username, email, first_name, last_name, middle_name, country_code, phone_number, created_at, password_changed_at FROM users WHERE username = ?");
    $stmt->execute([$_SESSION['user']]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user) {
        // Calculate password expiry information
        $passwordExpiryInfo = null;
        if ($user['password_changed_at']) {
            $changedTime = strtotime($user['password_changed_at']);
            $expiryTime = strtotime('+30 days', $changedTime);
            $currentTime = time();
            $daysUntilExpiry = ceil(($expiryTime - $currentTime) / (60 * 60 * 24));

            $passwordExpiryInfo = [
                'days_until_expiry' => max(0, $daysUntilExpiry),
                'is_expired' => $daysUntilExpiry <= 0,
                'changed_at' => $user['password_changed_at']
            ];
        }

        echo json_encode([
            'success' => true,
            'username' => $user['username'],
            'email' => $user['email'],
            'first_name' => $user['first_name'],
            'last_name' => $user['last_name'],
            'middle_name' => $user['middle_name'],
            'country_code' => $user['country_code'],
            'phone_number' => $user['phone_number'],
            'created_at' => $user['created_at'],
            'password_expiry' => $passwordExpiryInfo
        ]);
    } else {
        echo json_encode(['success' => false, 'message' => 'User not found']);
    }
} catch (PDOException $e) {
    echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
}
?>