<?php
declare(strict_types=1);
session_start();

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard | ParcelTrack Lite</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-100 min-h-screen p-8">
    <div class="max-w-xl mx-auto bg-white p-6 rounded shadow">
        <h1 class="text-2xl font-bold mb-1 text-slate-800">RapidExpress Dashboard</h1>
        <p class="text-slate-600 mb-6">User: <strong><?= htmlspecialchars($_SESSION['full_name'], ENT_QUOTES, 'UTF-8'); ?></strong> | Role: <span class="uppercase text-blue-600 font-bold"><?= htmlspecialchars($_SESSION['role'], ENT_QUOTES, 'UTF-8'); ?></span></p>
        
        <div class="space-y-3">
            <a href="change_password.php" class="block p-3 bg-slate-50 border rounded font-medium text-slate-700">Change Password</a>
            <?php if ($_SESSION['role'] === 'admin'): ?>
                <a href="create_rider.php" class="block p-3 bg-blue-50 border border-blue-200 rounded font-medium text-blue-700">Admin: Create Rider Account</a>
            <?php endif; ?>
            <a href="logout.php" class="block p-3 bg-red-50 border border-red-200 rounded font-medium text-red-600">Logout</a>
        </div>
    </div>
</body>
</html>