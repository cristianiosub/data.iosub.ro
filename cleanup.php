<?php
/**
 * DataTransfer - Script de curatare fisiere expirate
 *
 * Ruleaza manual sau prin cron job zilnic:
 *   https://data.iosub.ro/cleanup.php?secret=SETUP_KEY_VALUE
 *
 * Sau din CLI:
 *   php cleanup.php secret=SETUP_KEY_VALUE
 */

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/GoogleDrive.php';

// ── Verifica cheia secreta (suporta si CLI) ──────────────────────────────
if (PHP_SAPI === 'cli') {
    parse_str(implode('&', array_slice($argv, 1)), $cliArgs);
    $secret = $cliArgs['secret'] ?? '';
} else {
    $secret = $_GET['secret'] ?? '';
}

if (!hash_equals(SETUP_KEY, $secret)) {
    http_response_code(403);
    die('Acces interzis.');
}

// ── Curatare fisiere expirate ────────────────────────────────────────────
$db    = getDB();
$p     = DB_PREFIX;
$now   = date('Y-m-d H:i:s');
$stats = ['deleted_files' => 0, 'db_marked' => 0, 'errors' => 0, 'disk_freed' => 0];

// 1. Gaseste transferurile expirate care nu sunt inca marcate ca sterse
$expStmt = $db->prepare("
    SELECT id FROM `{$p}transfers`
    WHERE expires_at < ? AND deleted_at IS NULL
");
$expStmt->execute([$now]);
$expiredIds = $expStmt->fetchAll(PDO::FETCH_COLUMN);

// 2. Sterge fizic fisierele si marcheaza transferurile
$gdrive = null;
if (GDRIVE_ENABLED) {
    try {
        $gdrive = new GoogleDrive(GDRIVE_SA_KEY_FILE);
    } catch (RuntimeException $e) {
        error_log('Cleanup: GoogleDrive init error: ' . $e->getMessage());
    }
}

foreach ($expiredIds as $transferId) {
    $fStmt = $db->prepare("SELECT stored_name, file_size, drive_file_id FROM `{$p}files` WHERE transfer_id=?");
    $fStmt->execute([$transferId]);
    foreach ($fStmt->fetchAll() as $f) {
        $deleted = false;

        // Sterge din Google Drive daca are drive_file_id
        if (GDRIVE_ENABLED && $gdrive !== null && !empty($f['drive_file_id'])) {
            try {
                $ok = $gdrive->deleteFile($f['drive_file_id']);
                if ($ok) {
                    $stats['disk_freed'] += (int)$f['file_size'];
                    $stats['deleted_files']++;
                    $deleted = true;
                } else {
                    $stats['errors']++;
                    error_log("Cleanup: Nu s-a putut sterge din Drive: {$f['drive_file_id']}");
                }
            } catch (RuntimeException $e) {
                $stats['errors']++;
                error_log("Cleanup: Drive delete error: " . $e->getMessage());
            }
        }

        // Sterge si de pe disk local (compatibilitate cu fisierele vechi)
        if (!$deleted) {
            $path = UPLOAD_DIR . '/' . $f['stored_name'];
            if (file_exists($path)) {
                $stats['disk_freed'] += (int)$f['file_size'];
                if (@unlink($path)) {
                    $stats['deleted_files']++;
                } else {
                    $stats['errors']++;
                    error_log("Cleanup: Nu s-a putut sterge fisierul: {$path}");
                }
            }
        }
    }
    $db->prepare("UPDATE `{$p}transfers` SET deleted_at=? WHERE id=?")->execute([$now, $transferId]);
    $stats['db_marked']++;
}

// 3. Sterge definitiv din DB transferurile deja marcate (sterse mai demult)
$db->exec("DELETE FROM `{$p}files` WHERE transfer_id IN (
    SELECT id FROM `{$p}transfers` WHERE deleted_at IS NOT NULL
)");
$db->exec("DELETE FROM `{$p}transfers` WHERE deleted_at IS NOT NULL");

// 4. Curata log-uri mai vechi de 90 zile
$db->prepare("DELETE FROM `{$p}logs` WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY)")->execute();

// 5. Curata rate_limits vechi
$db->prepare("DELETE FROM `{$p}rate_limits` WHERE window_start < DATE_SUB(NOW(), INTERVAL 24 HOUR)")->execute();

// ── Log rezultat ─────────────────────────────────────────────────────────
$freedMB = round($stats['disk_freed'] / 1024 / 1024, 2);
$msg = sprintf(
    "[%s] Cleanup: %d transferuri expirate, %d fisiere sterse, %dMB eliberat, %d erori\n",
    date('Y-m-d H:i:s'),
    $stats['db_marked'],
    $stats['deleted_files'],
    $freedMB,
    $stats['errors']
);
error_log($msg);

if (PHP_SAPI !== 'cli') {
    header('Content-Type: text/plain; charset=utf-8');
}
echo $msg;
echo "Done.\n";
