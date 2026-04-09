<?php
// Debug login script
session_start();

include 'db.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = htmlspecialchars(stripslashes(trim($_POST['username'])));
    $password = $_POST['password'];

    echo "Attempting login for: $username<br>";

    try {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? OR email = ?");
        $stmt->execute([$username, $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            echo "User found: " . $user['username'] . " (ID: " . $user['id'] . ")<br>";
            echo "Email: " . $user['email'] . "<br>";
            echo "Verified: " . ($user['verified'] ? 'Yes' : 'No') . "<br>";
            echo "Password hash in DB: " . substr($user['password'], 0, 20) . "...<br>";

            if (password_verify($password, $user['password'])) {
                echo "Password correct<br>";

                if ($user['verified']) {
                    $_SESSION['user'] = $user['username'];
                    $_SESSION['user_id'] = $user['id'];
                    echo "Session set, redirecting...<br>";
                    echo "<script>window.location.href = 'dashboard.html';</script>";
                    exit;
                } else {
                    echo 'Account not verified.';
                }
            } else {
                echo 'Invalid password';
            }
        } else {
            echo 'User not found';
        }
    } catch (PDOException $e) {
        echo 'Database error: ' . $e->getMessage();
    }
} else {
    echo 'No POST data received';
}
?>