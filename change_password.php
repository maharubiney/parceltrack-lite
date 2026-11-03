<?php
declare(strict_types=1);
session_start();
require_once __DIR__ . '/db.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

$err = '';
$msg = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $currentPassword = (string)($_POST['current_password'] ?? '');
    $newPassword     = (string)($_POST['new_password'] ?? '');

    if (strlen($newPassword) < 10) {
        $err = "New password must be at least 10 characters long.";
    } else {
        $stmt = $pdo->prepare('SELECT password_hash FROM users WHERE user_id = :id LIMIT 1');
        $stmt->execute(['id' => $_SESSION['user_id']]);
        $user = $stmt->fetch();

        if ($user && password_verify($currentPassword, $user['password_hash'])) {
            $newHash = password_hash($newPassword, PASSWORD_BCRYPT, ['cost' => 12]);
            $upd = $pdo->prepare('UPDATE users SET password_hash = :hash WHERE user_id = :id');
            $upd->execute(['hash' => $newHash, 'id' => $_SESSION['user_id']]);
            $msg = "Password updated successfully.";
        } else {
            $err = "Incorrect current password.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Change Password | ParcelTrack Lite</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-100 flex items-center justify-center min-h-screen">
    <div class="bg-white p-8 rounded shadow-md w-full max-w-md">
        <h2 class="text-xl font-bold mb-4 text-center text-slate-800">Change Password</h2>
        <?php if ($err): ?><div class="bg-red-100 text-red-700 p-3 rounded mb-4 text-sm font-medium"><?= htmlspecialchars($err, ENT_QUOTES, 'UTF-8'); ?></div><?php endif; ?>
        <?php if ($msg): ?><div class="bg-green-100 text-green-700 p-3 rounded mb-4 text-sm font-medium"><?= htmlspecialchars($msg, ENT_QUOTES, 'UTF-8'); ?></div><?php endif; ?>
        <form method="POST" action="change_password.php" class="space-y-4">
            <div>
                <label class="block text-sm font-medium text-slate-700">Current Password</label>
                <input type="password" name="current_password" required class="w-full mt-1 p-2 border rounded">
            </div>
            <div>
                <label class="block text-sm font-medium text-slate-700">New Password (Min 10 characters)</label>
                <input type="password" name="new_password" minlength="10" required class="w-full mt-1 p-2 border rounded">
            </div>
            <button type="submit" class="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700 font-semibold">
                Update Password
            </button>
        </form>
        <p class="mt-4 text-center text-sm"><a href="dashboard.php" class="text-slate-600 underline">&larr; Return to Dashboard</a></p>
    </div>
</body>
</html>