<?php
/**
 * DataTransfer - Handler upload fisiere (suporta fisiere multiple)
 * Raspunde cu JSON.
 */

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/security.php';
require_once __DIR__ . '/GoogleDrive.php';

configureSecureSession();

header('Content-Type: application/json; charset=utf-8');
// Nu cache-ui niciodata raspunsuri de upload
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');
sendSecurityHeaders();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    die(json_encode(['error' => 'Metoda nepermisa.']));
}

// 1. CSRF
$csrfToken = $_POST['csrf_token'] ?? '';
if (!csrfTokenVerify($csrfToken)) {
    http_response_code(403);
    die(json_encode(['error' => 'Token CSRF invalid. Reimprospateaza pagina.']));
}

// 2. Rate limiting (max 1 upload/minut per IP si cookie)
$clientIP = getClientIP();
$uploadCookieId = getOrSetUploadCookie();
if (!rateLimitUpload($clientIP, $uploadCookieId)) {
    http_response_code(429);
    die(json_encode(['error' => 'Prea multe upload-uri. Poti trimite maxim un fisier pe minut.']));
}

// 3. Verifica fisiere
if (empty($_FILES['files'])) {
    http_response_code(400);
    die(json_encode(['error' => 'Nu a fost trimis niciun fisier.']));
}

// Normalizeaza structura $_FILES pentru upload multiplu
$filesRaw = $_FILES['files'];
$fileList = [];
$fileCount = is_array($filesRaw['name']) ? count($filesRaw['name']) : 1;

if (is_array($filesRaw['name'])) {
    for ($i = 0; $i < $fileCount; $i++) {
        $fileList[] = [
            'name'     => $filesRaw['name'][$i],
            'type'     => $filesRaw['type'][$i],
            'tmp_name' => $filesRaw['tmp_name'][$i],
            'error'    => $filesRaw['error'][$i],
            'size'     => $filesRaw['size'][$i],
        ];
    }
} else {
    $fileList[] = [
        'name'     => $filesRaw['name'],
        'type'     => $filesRaw['type'],
        'tmp_name' => $filesRaw['tmp_name'],
        'error'    => $filesRaw['error'],
        'size'     => $filesRaw['size'],
    ];
}

if (empty($fileList) || ($fileList[0]['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) {
    http_response_code(400);
    die(json_encode(['error' => 'Nu a fost trimis niciun fisier.']));
}

// 4. Expirare personalizabila
$expiryOptions = [1, 24, 168, 720]; // ore: 1h, 24h, 7d, 30d
$expiryHours   = (int)($_POST['expiry_hours'] ?? 720);
if (!in_array($expiryHours, $expiryOptions, true)) {
    $expiryHours = 720;
}

// 5. Valideaza si pregateste fisierele
$errMessages = [
    UPLOAD_ERR_INI_SIZE   => 'Fisierul depaseste limita serverului.',
    UPLOAD_ERR_FORM_SIZE  => 'Fisierul depaseste limita formularului.',
    UPLOAD_ERR_PARTIAL    => 'Fisierul a fost uploadat partial.',
    UPLOAD_ERR_NO_TMP_DIR => 'Directorul temporar lipsa.',
    UPLOAD_ERR_CANT_WRITE => 'Eroare la scriere pe disk.',
    UPLOAD_ERR_EXTENSION  => 'O extensie PHP a blocat upload-ul.',
];

$validatedFiles = [];
$totalSize = 0;
foreach ($fileList as $idx => $file) {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $msg = $errMessages[$file['error']] ?? "Eroare upload fisier #{$idx} (cod: {$file['error']}).";
        die(json_encode(['error' => $msg]));
    }
    $validation = validateUploadedFile($file);
    if (!$validation['ok']) {
        http_response_code(400);
        die(json_encode(['error' => "Fisier #{$idx} ({$file['name']}): " . $validation['error']]));
    }
    $originalName = sanitizeFilename($file['name']);
    if (empty($originalName)) $originalName = 'fisier_' . ($idx + 1);
    $totalSize += (int)$file['size'];
    $validatedFiles[] = [
        'tmp_name'      => $file['tmp_name'],
        'original_name' => $originalName,
        'file_size'     => (int)$file['size'],
        'mime_type'     => $validation['mime'],
    ];
}

// 6. Creeaza directorul de upload local (folosit doar cand GDRIVE_ENABLED=false)
if (!GDRIVE_ENABLED && !is_dir(UPLOAD_DIR)) {
    if (!mkdir(UPLOAD_DIR, 0750, true)) {
        http_response_code(500);
        die(json_encode(['error' => 'Nu s-a putut crea directorul de stocare.']));
    }
    file_put_contents(UPLOAD_DIR . '/index.php', '<?php http_response_code(403); die();');
    file_put_contents(UPLOAD_DIR . '/.htaccess',
        "Options -Indexes\nDeny from all\n" .
        "<FilesMatch \".*\">\n  Order Allow,Deny\n  Deny from all\n</FilesMatch>\n"
    );
}

// 7. Parametri comuni transferului
$message      = sanitizeString($_POST['message'] ?? '', 1000);
$password     = substr(trim($_POST['password'] ?? ''), 0, 200);
$passwordHash = null;
if ($password !== '') {
    $passwordHash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
}

// Determina numele bundle-ului
$bundleName = count($validatedFiles) === 1
    ? $validatedFiles[0]['original_name']
    : count($validatedFiles) . ' fisiere';

$token      = generateToken();
$now        = date('Y-m-d H:i:s');
$expiresAt  = date('Y-m-d H:i:s', strtotime("+{$expiryHours} hours"));
$uploaderUA = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500);

// 8. Salveaza in DB (tranzactie)
$db = getDB();
$p  = DB_PREFIX;
try {
    $db->beginTransaction();

    $stmt = $db->prepare("
        INSERT INTO `{$p}transfers`
            (token, bundle_name, file_count, total_size, password_hash, max_downloads,
             message, uploader_ip, uploader_ua, expiry_hours, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ");
    $stmt->execute([
        $token,
        $bundleName,
        count($validatedFiles),
        $totalSize,
        $passwordHash,
        (int)MAX_DOWNLOADS,
        $message ?: null,
        $clientIP,
        $uploaderUA,
        $expiryHours,
        $now,
        $expiresAt,
    ]);
    $transferId = (int)$db->lastInsertId();

    // Salveaza fisierele (pe Drive sau pe disk) si insereaza in dt_files
    $movedFiles = []; // pentru rollback (disk local)
    $driveIds   = []; // pentru rollback (Drive)

    $fStmt = $db->prepare("
        INSERT INTO `{$p}files` (transfer_id, stored_name, original_name, file_size, mime_type, drive_file_id)
        VALUES (?, ?, ?, ?, ?, ?)
    ");

    $gdrive = null;
    if (GDRIVE_ENABLED) {
        try {
            $gdrive = new GoogleDrive(GDRIVE_SA_KEY_FILE);
        } catch (RuntimeException $e) {
            error_log('GoogleDrive init error: ' . $e->getMessage());
            $db->rollBack();
            http_response_code(500);
            die(json_encode(['error' => 'Eroare la initializarea stocarii in cloud.']));
        }
    }

    foreach ($validatedFiles as $vf) {
        $storedName  = bin2hex(random_bytes(16)); // 32 hex — folosit ca identificator local
        $driveFileId = null;

        if (GDRIVE_ENABLED && $gdrive !== null) {
            // ── Stocare pe Google Drive ──────────────────────────────────
            try {
                $driveFileId = $gdrive->uploadFile(
                    $vf['tmp_name'],
                    $vf['original_name'],
                    $vf['mime_type'],
                    GDRIVE_FOLDER_ID
                );
                $driveIds[] = $driveFileId;
            } catch (RuntimeException $e) {
                // Rollback: sterge fisierele deja uploadate pe Drive
                foreach ($driveIds as $did) {
                    try { $gdrive->deleteFile($did); } catch (RuntimeException) {}
                }
                $db->rollBack();
                error_log('Drive upload error: ' . $e->getMessage());
                http_response_code(500);
                die(json_encode(['error' => 'Eroare la salvarea in cloud. Incearca din nou.']));
            }
        } else {
            // ── Stocare locala (fallback) ────────────────────────────────
            $destPath      = UPLOAD_DIR . '/' . $storedName;
            $realUploadDir = realpath(UPLOAD_DIR);
            $expectedPath  = $realUploadDir . DIRECTORY_SEPARATOR . $storedName;
            if ($realUploadDir === false || strpos($expectedPath, $realUploadDir . DIRECTORY_SEPARATOR) !== 0) {
                foreach ($movedFiles as $mp) { @unlink($mp); }
                $db->rollBack();
                http_response_code(500);
                die(json_encode(['error' => 'Eroare interna de cale.']));
            }
            if (!move_uploaded_file($vf['tmp_name'], $destPath)) {
                foreach ($movedFiles as $mp) { @unlink($mp); }
                $db->rollBack();
                http_response_code(500);
                die(json_encode(['error' => 'Nu s-a putut salva fisierul pe server.']));
            }
            chmod($destPath, 0600);
            $movedFiles[] = $destPath;
        }

        $fStmt->execute([
            $transferId,
            $storedName,
            $vf['original_name'],
            $vf['file_size'],
            $vf['mime_type'],
            $driveFileId,
        ]);
    }

    $db->commit();
} catch (PDOException $e) {
    $db->rollBack();
    error_log('Upload DB error: ' . $e->getMessage());
    http_response_code(500);
    die(json_encode(['error' => 'Eroare la salvarea in baza de date.']));
}

// 9. Log upload
logEvent($transferId, 'upload', $clientIP, $uploaderUA);

// 10. Raspuns
$downloadUrl = BASE_URL . '/download.php?token=' . urlencode($token);
echo json_encode([
    'success'      => true,
    'url'          => $downloadUrl,
    'token'        => $token,
    'expires_at'   => $expiresAt,
    'expiry_hours' => $expiryHours,
    'has_password' => ($passwordHash !== null),
    'file_count'   => count($validatedFiles),
    'total_size'   => $totalSize,
    'bundle_name'  => $bundleName,
]);
