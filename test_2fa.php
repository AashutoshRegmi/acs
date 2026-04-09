<?php
require_once 'db.php';
require_once 'vendor/autoload.php';

use Sonata\GoogleAuthenticator\GoogleAuthenticator;

try {
    // Test database connection and schema
    $stmt = $pdo->query('SELECT COUNT(*) as user_count FROM users');
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    echo "✓ Database connection works, users table has {$result['user_count']} records\n";

    // Test 2FA columns
    $stmt = $pdo->query('DESCRIBE users');
    $columns = $stmt->fetchAll(PDO::FETCH_COLUMN);
    $required = ['twofa_secret', 'twofa_enabled'];

    foreach ($required as $col) {
        if (in_array($col, $columns)) {
            echo "✓ $col column exists\n";
        } else {
            echo "✗ $col column missing\n";
        }
    }

    // Test backup codes table
    $stmt = $pdo->query('SHOW TABLES LIKE "twofa_backup_codes"');
    if ($stmt->rowCount() > 0) {
        echo "✓ twofa_backup_codes table exists\n";
    } else {
        echo "✗ twofa_backup_codes table does not exist\n";
    }

    // Test Google Authenticator library
    $g = new GoogleAuthenticator();
    $secret = $g->generateSecret();
    $code = $g->getCode($secret);

    if (strlen($secret) === 16 && is_numeric($code) && strlen($code) === 6) {
        echo "✓ Google Authenticator library works\n";
    } else {
        echo "✗ Google Authenticator library not working\n";
    }

    echo "Database and library check complete\n";

} catch (Exception $e) {
    echo 'Error: ' . $e->getMessage() . "\n";
}
?>