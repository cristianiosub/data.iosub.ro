<?php
/**
 * DataTransfer - Conexiune baza de date si initializare schema
 */

require_once __DIR__ . '/config.php';

function getDB(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        try {
            $dsn = sprintf(
                'mysql:host=%s;dbname=%s;charset=%s',
                DB_HOST, DB_NAME, DB_CHARSET
            );
            $pdo = new PDO($dsn, DB_USER, DB_PASS, [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
                PDO::MYSQL_ATTR_FOUND_ROWS   => true,
            ]);
        } catch (PDOException $e) {
            error_log('DB Connection failed: ' . $e->getMessage());
            http_response_code(500);
            die(json_encode(['error' => 'Eroare de conexiune la baza de date.']));
        }
    }
    return $pdo;
}

function initDB(): void
{
    $db = getDB();
    $p  = DB_PREFIX;

    // Tabela principala - transferuri (un transfer = un bundle de fisiere)
    $db->exec("
        CREATE TABLE IF NOT EXISTS `{$p}transfers` (
            `id`             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            `token`          VARCHAR(64)  NOT NULL UNIQUE,
            `bundle_name`    VARCHAR(500) NOT NULL,
            `file_count`     INT UNSIGNED NOT NULL DEFAULT 1,
            `total_size`     BIGINT UNSIGNED NOT NULL DEFAULT 0,
            `password_hash`  VARCHAR(255) DEFAULT NULL,
            `download_count` INT UNSIGNED DEFAULT 0,
            `max_downloads`  INT UNSIGNED DEFAULT 0,
            `message`        TEXT         DEFAULT NULL,
            `uploader_ip`    VARCHAR(45)  NOT NULL,
            `uploader_ua`    VARCHAR(500) DEFAULT NULL,
            `expiry_hours`   INT UNSIGNED NOT NULL DEFAULT 720,
            `created_at`     DATETIME     NOT NULL,
            `expires_at`     DATETIME     NOT NULL,
            `deleted_at`     DATETIME     DEFAULT NULL,
            INDEX `idx_token`   (`token`),
            INDEX `idx_expires` (`expires_at`),
            INDEX `idx_deleted` (`deleted_at`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");

    // Tabela fisiere - fiecare fisier dintr-un transfer
    $db->exec("
        CREATE TABLE IF NOT EXISTS `{$p}files` (
            `id`             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            `transfer_id`    INT UNSIGNED NOT NULL,
            `stored_name`    VARCHAR(64)  NOT NULL UNIQUE,
            `original_name`  VARCHAR(500) NOT NULL,
            `file_size`      BIGINT UNSIGNED NOT NULL,
            `mime_type`      VARCHAR(200) NOT NULL,
            `drive_file_id`  VARCHAR(200) DEFAULT NULL,
            INDEX `idx_transfer` (`transfer_id`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");

    // Adauga coloana drive_file_id daca tabela exista deja si coloana lipseste
    try {
        $db->exec("ALTER TABLE `{$p}files` ADD COLUMN IF NOT EXISTS `drive_file_id` VARCHAR(200) DEFAULT NULL");
    } catch (PDOException) {
        // MySQL < 8.0 nu suporta IF NOT EXISTS pe ALTER — incercam cu un check manual
        $cols = $db->query("SHOW COLUMNS FROM `{$p}files` LIKE 'drive_file_id'")->fetchAll();
        if (empty($cols)) {
            $db->exec("ALTER TABLE `{$p}files` ADD COLUMN `drive_file_id` VARCHAR(200) DEFAULT NULL");
        }
    }

    // Tabela log-uri - upload + download events cu IP, user agent
    $db->exec("
        CREATE TABLE IF NOT EXISTS `{$p}logs` (
            `id`           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            `transfer_id`  INT UNSIGNED NOT NULL,
            `event_type`   ENUM('upload','download') NOT NULL,
            `ip`           VARCHAR(45)  NOT NULL,
            `user_agent`   VARCHAR(500) DEFAULT NULL,
            `os_name`      VARCHAR(100) DEFAULT NULL,
            `browser_name` VARCHAR(100) DEFAULT NULL,
            `created_at`   DATETIME     NOT NULL,
            INDEX `idx_transfer_log` (`transfer_id`),
            INDEX `idx_event`        (`event_type`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");

    // Tabela rate limiting
    $db->exec("
        CREATE TABLE IF NOT EXISTS `{$p}rate_limits` (
            `ip`           VARCHAR(45)  NOT NULL PRIMARY KEY,
            `upload_count` INT UNSIGNED DEFAULT 0,
            `window_start` DATETIME     NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ");

    // Tabela admini
    $db->exec("
        CREATE TABLE IF NOT EXISTS `{$p}admins` (
            `id`            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            `username`      VARCHAR(100) NOT NULL UNIQUE,
            `password_hash` VARCHAR(255) NOT NULL,
            `created_at`    DATETIME     NOT NULL,
            `last_login_at` DATETIME     DEFAULT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");
}

/**
 * Parseaza user agent si intoarce OS + browser (simplu, fara librarie externa)
 */
function parseUserAgent(string $ua): array
{
    $os = 'Necunoscut';
    $browser = 'Necunoscut';

    // OS detection
    $osList = [
        'Windows 11'    => 'Windows NT 10.0',   // Win11 raporteaza tot NT 10
        'Windows 10'    => 'Windows NT 10.0',
        'Windows 8.1'   => 'Windows NT 6.3',
        'Windows 8'     => 'Windows NT 6.2',
        'Windows 7'     => 'Windows NT 6.1',
        'Android'       => 'Android',
        'iPhone'        => 'iPhone',
        'iPad'          => 'iPad',
        'macOS'         => 'Macintosh',
        'Linux'         => 'Linux',
    ];
    // Detectie mai fina Windows 11 (nu e posibil 100% din UA, dar incercam)
    foreach ($osList as $name => $sig) {
        if (stripos($ua, $sig) !== false) {
            $os = $name;
            break;
        }
    }
    if ($os === 'Windows 10' && preg_match('/Windows NT 10\.0.*rv:(\d+)/', $ua, $m) && (int)$m[1] >= 90) {
        // Heuristic: Firefox >= 90 pe Win11 exista
    }

    // Browser detection (ordinea conteaza!)
    if (stripos($ua, 'Edg/') !== false || stripos($ua, 'Edge/') !== false) {
        $browser = 'Microsoft Edge';
    } elseif (stripos($ua, 'OPR/') !== false || stripos($ua, 'Opera') !== false) {
        $browser = 'Opera';
    } elseif (stripos($ua, 'SamsungBrowser') !== false) {
        $browser = 'Samsung Browser';
    } elseif (stripos($ua, 'Chrome/') !== false) {
        $browser = 'Chrome';
    } elseif (stripos($ua, 'Firefox/') !== false) {
        $browser = 'Firefox';
    } elseif (stripos($ua, 'Safari/') !== false) {
        $browser = 'Safari';
    } elseif (stripos($ua, 'MSIE') !== false || stripos($ua, 'Trident/') !== false) {
        $browser = 'Internet Explorer';
    }

    return ['os' => $os, 'browser' => $browser];
}

/**
 * Inregistreaza un eveniment de upload sau download
 */
function logEvent(int $transferId, string $eventType, string $ip, string $ua = ''): void
{
    try {
        $db = getDB();
        $p  = DB_PREFIX;
        $parsed = parseUserAgent($ua);
        $db->prepare("
            INSERT INTO `{$p}logs` (transfer_id, event_type, ip, user_agent, os_name, browser_name, created_at)
            VALUES (?, ?, ?, ?, ?, ?, NOW())
        ")->execute([
            $transferId,
            $eventType,
            $ip,
            substr($ua, 0, 500),
            $parsed['os'],
            $parsed['browser'],
        ]);
    } catch (PDOException $e) {
        error_log('logEvent error: ' . $e->getMessage());
    }
}
