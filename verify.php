<?php
// Email verification script

include 'db.php';

if (isset($_GET['token'])) {
    $token = $_GET['token'];
    try {
        $stmt = $pdo->prepare("UPDATE users SET verified = TRUE, token = NULL WHERE token = ?");
        $stmt->execute([$token]);
        if ($stmt->rowCount() > 0) {
            echo 'Account verified successfully. You can now <a href="login.html">login</a>.';
        } else {
            echo 'Invalid or expired token.';
        }
    } catch (PDOException $e) {
        echo 'Database error: ' . $e->getMessage();
    }
} else {
    echo 'No token provided.';
}
?>