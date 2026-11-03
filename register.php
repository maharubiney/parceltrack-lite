<?php
declare(strict_types=1);
session_start();
require_once __DIR__ . '/db.php';

$err = '';
$msg = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $fullName = trim((string)($_POST['full_name'] ?? ''));
    $email    = filter_var(trim($_POST['email'] ?? ''), FILTER_VALIDATE_EMAIL);
    $password = (string)($_POST['password'] ?? '');

    if (!$email || strlen($fullName) < 3) {
        $err = "Please enter a valid name and email address.";
    } elseif (strlen($password) < 10) {
        // Enforcing Policy P2: Passwords must be at least 10 characters
        $err = "Password must be at least 10 characters long.";
    } else {
        $stmt = $pdo->prepare('SELECT user_id FROM users WHERE email = :email LIMIT 1');
        $stmt->execute(['email' => $email]);
        if ($stmt->fetch()) {
            $err = "An account with this email already exists.";
        } else {
            $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
            $ins  = $pdo->prepare('INSERT INTO users (full_name, email, password_hash, role, is_active) VALUES (:name, :email, :hash, "seller", 1)');
            $ins->execute([
                'name'  => htmlspecialchars($fullName, ENT_QUOTES, 'UTF-8'),
                'email' => $email,
                'hash'  => $hash
            ]);
            $msg = "Seller registration successful. Please log in.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Seller Registration | ParcelTrack Lite</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-100 flex items-center justify-center min-h-screen">
    <div class="bg-white p-8 rounded shadow-md w-full max-w-md">
        <h2 class="text-2xl font-bold mb-4 text-center text-slate-800">Seller Self-Registration</h2>
        <?php if ($err): ?><div class="bg-red-100 text-red-700 p-3 rounded mb-4 text-sm font-medium"><?= htmlspecialchars($err, ENT_QUOTES, 'UTF-8'); ?></div><?php endif; ?>
        <?php if ($msg): ?><div class="bg-green-100 text-green-700 p-3 rounded mb-4 text-sm font-medium"><?= htmlspecialchars($msg, ENT_QUOTES, 'UTF-8'); ?></div><?php endif; ?>
        <form method="POST" action="register.php" class="space-y-4">
            <div>
                <label class="block text-sm font-medium text-slate-700">Full Name / Business Name</label>
                <input type="text" name="full_name" required class="w-full mt-1 p-2 border rounded">
            </div>
            <div>
                <label class="block text-sm font-medium text-slate-700">Email Address</label>
                <input type="email" name="email" required class="w-full mt-1 p-2 border rounded">
            </div>
            <div>
                <label class="block text-sm font-medium text-slate-700">Password (Min 10 characters)</label>
                <input type="password" name="password" minlength="10" required class="w-full mt-1 p-2 border rounded">
            </div>
            <button type="submit" class="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700 font-semibold">
                Register Seller Account
            </button>
        </form>
        <p class="mt-4 text-center text-sm">
            Already registered? <a href="login.php" class="text-blue-600 underline">Back to Login</a>
        </p>
    </div>
</body>
</html>