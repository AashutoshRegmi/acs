<?php
session_start();
require_once 'db.php';

header('Content-Type: application/json');

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    echo json_encode(['success' => false, 'message' => 'Please log in to view activity log.']);
    exit;
}

$user_id = $_SESSION['user_id'];

try {
    // Get activity logs for the user
    $stmt = $pdo->prepare("
        SELECT action, details, ip_address, timestamp
        FROM activity_logs
        WHERE user_id = ?
        ORDER BY timestamp DESC
        LIMIT 50
    ");
    $stmt->execute([$user_id]);
    $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Format the logs
    $formatted_logs = array_map(function($log) {
        return [
            'action' => $log['action'],
            'details' => $log['details'] ?: '',
            'ip_address' => $log['ip_address'] ?: 'Unknown',
            'timestamp' => date('M d, Y H:i:s', strtotime($log['timestamp']))
        ];
    }, $logs);

    echo json_encode([
        'success' => true,
        'logs' => $formatted_logs
    ]);

} catch (PDOException $e) {
    error_log('Activity log error: ' . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'An error occurred while retrieving activity logs.']);
}
?>