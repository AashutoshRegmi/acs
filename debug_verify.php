<?php
// Debug script to check token verification
include 'db.php';

if (isset($_GET['token'])) {
    $token = $_GET['token'];

    echo "Received token: " . htmlspecialchars($token) . "<br>";
    echo "Token length: " . strlen($token) . "<br>";

    try {
        // First, let's see what tokens exist in the database
        $stmt = $pdo->query("SELECT token FROM users WHERE token IS NOT NULL");
        $tokens = $stmt->fetchAll(PDO::FETCH_ASSOC);

        echo "Tokens in database:<br>";
        foreach ($tokens as $dbToken) {
            echo "- " . htmlspecialchars($dbToken['token']) . " (length: " . strlen($dbToken['token']) . ")<br>";
            if ($dbToken['token'] === $token) {
                echo "<strong>MATCH FOUND!</strong><br>";
            }
        }

        // Now try the update
        $stmt = $pdo->prepare("UPDATE users SET verified = TRUE, token = NULL WHERE token = ?");
        $stmt->execute([$token]);

        if ($stmt->rowCount() > 0) {
            echo '<br>Account verified successfully. You can now <a href="login.html">login</a>.';
        } else {
            echo '<br>Invalid or expired token.';
        }
    } catch (PDOException $e) {
        echo 'Database error: ' . $e->getMessage();
    }
} else {
    echo 'No token provided.';
}
?>