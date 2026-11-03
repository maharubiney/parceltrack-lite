<?php
declare(strict_types=1);
session_start();
require_once __DIR__ . '/db.php';

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = filter_var(trim($_POST['email'] ?? ''), FILTER_VALIDATE_EMAIL);
    $password = (string)($_POST['password'] ?? '');

    if (!$email || empty($password)) {
        $error = "Invalid email or password.";
    } else {

        $stmt = $pdo->prepare('SELECT user_id, full_name, password_hash, role, failed_attempts, lockout_until, is_active FROM users WHERE email = :email LIMIT 1');
        $stmt->execute(['email' => $email]);
        $user = $stmt->fetch();

        $now = new DateTimeImmutable();

        if ($user && $user['lockout_until'] && new DateTimeImmutable($user['lockout_until']) > $now) {
            $error = "Account is temporarily locked due to multiple failed login attempts. Please try again later.";
        } else {

            if ($user && (int)$user['is_active'] === 1 && password_verify($password, $user['password_hash'])) {

                $reset = $pdo->prepare('UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE user_id = :id');
                $reset->execute(['id' => $user['user_id']]);

                session_regenerate_id(true);
                $_SESSION['user_id']   = $user['user_id'];
                $_SESSION['role']      = $user['role'];
                $_SESSION['full_name'] = $user['full_name'];

                $log = $pdo->prepare('INSERT INTO audit_logs (user_id, action, ip_address, status_flag) VALUES (:uid, "LOGIN_SUCCESS", :ip, 1)');
                $log->execute(['uid' => $user['user_id'], 'ip' => $_SERVER['REMOTE_ADDR']]);

                header("Location: dashboard.php");
                exit;
            } else {
                if ($user) {
                    $attempts = (int)$user['failed_attempts'] + 1;
                    $lockoutTime = ($attempts >= 5) ? (new DateTimeImmutable('+15 minutes'))->format('Y-m-d H:i:s') : null;
                    $upd = $pdo->prepare('UPDATE users SET failed_attempts = :att, lockout_until = :lock WHERE user_id = :id');
                    $upd->execute(['att' => $attempts, 'lock' => $lockoutTime, 'id' => $user['user_id']]);
                }

                $log = $pdo->prepare('INSERT INTO audit_logs (user_id, action, ip_address, status_flag) VALUES (:uid, "LOGIN_FAILED", :ip, 0)');
                $log->execute(['uid' => $user['user_id'] ?? null, 'ip' => $_SERVER['REMOTE_ADDR']]);

                $error = "Invalid email or password.";
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ParcelTrack Lite | Login</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-100 flex items-center justify-center min-h-screen">
    <div class="bg-white p-8 rounded shadow-md w-full max-w-md">
        <h2 class="text-2xl font-bold mb-4 text-center text-slate-800">RapidExpress Login</h2>
        <?php if ($error): ?>
            <div class="bg-red-100 text-red-700 p-3 rounded mb-4 text-sm font-medium">
                <?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?>
            </div>
        <?php endif; ?>
        <form method="POST" action="login.php" class="space-y-4">
            <div>
                <label class="block text-sm font-medium text-slate-700">Email Address</label>
                <input type="email" name="email" required class="w-full mt-1 p-2 border rounded">
            </div>
            <div>
                <label class="block text-sm font-medium text-slate-700">Password</label>
                <input type="password" name="password" required class="w-full mt-1 p-2 border rounded">
            </div>
            <button type="submit" class="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700 font-semibold">
                Sign In
            </button>
        </form>
        <p class="mt-4 text-center text-sm">
            Seller? <a href="register.php" class="text-blue-600 underline">Register here</a>
        </p>
    </div>
</body>
</html>