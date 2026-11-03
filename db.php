<?php
declare(strict_types=1);

$envPath = __DIR__ . '/.env';
if (!file_exists($envPath)) {
    exit("System configuration unavailable.");
}

$env = parse_ini_file($envPath);

$host    = $env['DB_HOST'] ?? '';
$db      = $env['DB_NAME'] ?? '';
$user    = $env['DB_USER'] ?? '';
$pass    = $env['DB_PASS'] ?? '';
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false, // Enforce true parameterised queries against SQLi
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (PDOException $e) {
    // Policy P4: Technical details to server log only, generic message to users
    error_log("Database connection error: " . $e->getMessage());
    exit("A system error occurred. Please try again later.");
}