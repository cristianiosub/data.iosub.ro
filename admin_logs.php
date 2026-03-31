<?php
/**
 * DataTransfer - Endpoint AJAX pentru log-urile unui transfer (folosit de admin.php)
 */
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/security.php';
if (session_status() === PHP_SESSION_NONE) session_start();
header('Content-Type: application/json; charset=utf-8');
sendSecurityHeaders();

// Trebuie sa fie autentificat ca admin
if (!isset($_SESSION['admin_id'])) {
    http_response_code(403);
    die(json_encode(['error' => 'Acces interzis.']));
}

$token = trim($_GET['token'] ?? '');
if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
    http_response_code(400);
    die(json_encode(['error' => 'Token invalid.']));
}

$db = getDB(); $p = DB_PREFIX;
$stmt = $db->prepare("SELECT id, bundle_name FROM `{$p}transfers` WHERE token=? LIMIT 1");
$stmt->execute([$token]); $transfer = $stmt->fetch();
if (!$transfer) {
    http_response_code(404);
    die(json_encode(['error' => 'Transfer negăsit.']));
}

$lStmt = $db->prepare("
    SELECT event_type, ip, os_name, browser_name, user_agent,
           DATE_FORMAT(created_at, '%d.%m.%Y %H:%i:%s') as created_at
    FROM `{$p}logs`
    WHERE transfer_id=?
    ORDER BY created_at DESC
    LIMIT 200
");
$lStmt->execute([$transfer['id']]);
$logs = $lStmt->fetchAll();

echo json_encode([
    'bundle_name' => $transfer['bundle_name'],
    'logs'        => $logs,
]);
