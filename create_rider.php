<?php
declare(strict_types=1);
session_start();
require_once __DIR__ . '/db.php';


if (!isset($_SESSION['user_id']) || ($_SESSION['role'] ?? '') !== 'admin') {
    http_response_code(403);
    exit("Access Denied: Only Admin can create Rider accounts.");
}

$err = '';
$msg = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $riderName    = trim((string)($_POST['rider_name'] ?? ''));
    $email        = filter_var(trim($_POST['email'] ?? ''), FILTER_VALIDATE_EMAIL);
    $tempPassword = (string)($_POST['temp_password'] ?? '');

    if (!$email || strlen($riderName) < 2) {
        $err = "Invalid rider name or email.";
    } elseif (strlen($tempPassword) < 10) {
        $err = "Temporary password must be at least 10 characters long.";
    } else {
        $stmt = $pdo->prepare('SELECT user_id FROM users WHERE email = :email LIMIT 1');
        $stmt->execute(['email' => $email]);
        if ($stmt->fetch()) {
            $err = "An account with this email already exists.";
        } else {
            $hash = password_hash($tempPassword, PASSWORD_BCRYPT, ['cost' => 12]);
            $ins  = $pdo->prepare('INSERT INTO users (full_name, email, password_hash, role, is_active) VALUES (:name, :email, :hash, "rider", 1)');
            $ins->execute([
                'name'  => htmlspecialchars($riderName, ENT_QUOTES, 'UTF-8'),
                'email' => $email,
                'hash'  => $hash
            ]);
            $msg = "Rider account successfully created.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Create Rider | Admin</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-100 p-8">
    <div class="max-w-md mx-auto bg-white p-6 rounded shadow">
        <h2 class="text-xl font-bold mb-4 text-slate-800">Admin: Create Rider Account</h2>
        <?php if ($err): ?><div class="bg-red-100 text-red-700 p-3 rounded mb-4 text-sm font-medium"><?= htmlspecialchars($err, ENT_QUOTES, 'UTF-8'); ?></div><?php endif; ?>
        <?php if ($msg): ?><div class="bg-green-100 text-green-700 p-3 rounded mb-4 text-sm font-medium"><?= htmlspecialchars($msg, ENT_QUOTES, 'UTF-8'); ?></div><?php endif; ?>
        <form method="POST" action="create_rider.php" class="space-y-4">
            <div>
                <label class="block text-sm font-medium text-slate-700">Rider Full Name</label>
                <input type="text" name="rider_name" required class="w-full mt-1 p-2 border rounded">
            </div>
            <div>
                <label class="block text-sm font-medium text-slate-700">Rider Email</label>
                <input type="email" name="email" required class="w-full mt-1 p-2 border rounded">
            </div>
            <div>
                <label class="block text-sm font-medium text-slate-700">Temporary Password (Min 10 characters)</label>
                <input type="password" name="temp_password" minlength="10" required class="w-full mt-1 p-2 border rounded">
            </div>
            <button type="submit" class="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700 font-semibold">
                Create Rider
            </button>
        </form>
        <p class="mt-4 text-sm"><a href="dashboard.php" class="text-slate-600 underline">&larr; Return to Dashboard</a></p>
    </div>
</body>
</html>