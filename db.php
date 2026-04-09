<?php
// Database connection
require_once 'env.php';

$host = env('DB_HOST', '');
$port = env('DB_PORT', '3306');
$dbname = env('DB_NAME', '');
$username = env('DB_USER', '');
$password = env('DB_PASS', '');

try {
    $pdo = new PDO("mysql:host=$host;port=$port;charset=utf8mb4", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    // Create database if not exists
    $pdo->exec("CREATE DATABASE IF NOT EXISTS `$dbname`");
    $pdo->exec("USE `$dbname`");

    // Create users table if not exists (with proper schema)
    $sql = "CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        username VARCHAR(255) UNIQUE NOT NULL,
        first_name VARCHAR(100) NOT NULL,
        middle_name VARCHAR(100) NULL,
        last_name VARCHAR(100) NOT NULL,
        country_code VARCHAR(10) NOT NULL,
        phone_number VARCHAR(20) NOT NULL,
        password VARCHAR(255) NOT NULL,
        verified BOOLEAN DEFAULT FALSE,
        token VARCHAR(64) NULL,
        otp VARCHAR(6) NULL,
        otp_expires TIMESTAMP NULL,
        otp_failed_attempts INT DEFAULT 0,
        otp_cooldown_until TIMESTAMP NULL,
        password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        login_attempts INT DEFAULT 0,
        locked_until TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )";
    $pdo->exec($sql);

    // Add last_ip column if not exists
    try {
        $pdo->exec("ALTER TABLE users ADD COLUMN last_ip VARCHAR(45) NULL");
    } catch (Exception $e) {
        // Column might already exist
    }

    // Create password history table
    $sql = "CREATE TABLE IF NOT EXISTS password_history (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )";
    $pdo->exec($sql);

    // Create password reset tokens table
    $sql = "CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        token VARCHAR(64) UNIQUE NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        used BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_token (token),
        INDEX idx_expires_at (expires_at)
    )";
    $pdo->exec($sql);

    // Create backup codes table for 2FA
    $sql = "CREATE TABLE IF NOT EXISTS twofa_backup_codes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        code VARCHAR(10) NOT NULL,
        used BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE KEY unique_code_per_user (user_id, code)
    )";
    $pdo->exec($sql);

    // Create activity logs table
    $sql = "CREATE TABLE IF NOT EXISTS activity_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        action VARCHAR(255) NOT NULL,
        details TEXT NULL,
        ip_address VARCHAR(45) NULL,
        user_agent TEXT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_user_id (user_id),
        INDEX idx_timestamp (timestamp)
    )";
    $pdo->exec($sql);

    // Add password history columns if they don't exist (for backward compatibility)
    try {
        $pdo->exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP AFTER otp_expires");
        $pdo->exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS otp_failed_attempts INT DEFAULT 0 AFTER otp_expires");
        $pdo->exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS otp_cooldown_until TIMESTAMP NULL AFTER otp_failed_attempts");
        $pdo->exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS login_attempts INT DEFAULT 0 AFTER password_changed_at");
        $pdo->exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP NULL AFTER login_attempts");
        $pdo->exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_ip VARCHAR(45) NULL AFTER locked_until");
        $pdo->exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS twofa_secret VARCHAR(32) NULL AFTER last_ip");
        $pdo->exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS twofa_enabled TINYINT(1) DEFAULT 0 AFTER twofa_secret");
    } catch (PDOException $e) {
        // Ignore errors if columns already exist
    }

} catch (PDOException $e) {
    die("Database setup failed: " . $e->getMessage());
}

// Function to log user activities
function logActivity($pdo, $user_id, $action, $details = null) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? null;
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? null;
    try {
        $stmt = $pdo->prepare("INSERT INTO activity_logs (user_id, action, details, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)");
        $stmt->execute([$user_id, $action, $details, $ip, $user_agent]);
    } catch (PDOException $e) {
        // Log to error log if database logging fails
        error_log("Failed to log activity: " . $e->getMessage());
    }
}
?>