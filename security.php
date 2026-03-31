<?php
/**
 * DataTransfer - Functii de securitate
 *
 * Contine: CSRF, rate limiting, validare fisier (extensie + MIME + magic bytes),
 *          sanitizare input, detectare executabile/virusi, security headers
 */

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';

// ================================================================
// SESSION SECURIZATA - trebuie apelata INAINTE de session_start()
// ================================================================

function configureSecureSession(): void
{
    if (session_status() !== PHP_SESSION_NONE) return;

    // Cookie flags: Secure, HttpOnly, SameSite=Strict
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'domain'   => '',
        'secure'   => true,   // Doar HTTPS
        'httponly' => true,   // Nu accesibil din JS
        'samesite' => 'Strict',
    ]);

    // ID-uri lungi si aleatorii
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.use_trans_sid', '0');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_secure', '1');
    ini_set('session.cookie_samesite', 'Strict');
    ini_set('session.sid_length', '48');
    ini_set('session.sid_bits_per_character', '6');

    session_start();
}

// ================================================================
// CSRF Protection
// ================================================================

function csrfTokenGenerate(): string
{
    if (session_status() === PHP_SESSION_NONE) {
        configureSecureSession();
    }
    if (empty($_SESSION['csrf_token']) || empty($_SESSION['csrf_token_time'])) {
        $_SESSION['csrf_token']      = bin2hex(random_bytes(32));
        $_SESSION['csrf_token_time'] = time();
    }
    // Regenereaza token-ul dupa 30 minute de inactivitate
    if ((time() - ($_SESSION['csrf_token_time'] ?? 0)) > 1800) {
        $_SESSION['csrf_token']      = bin2hex(random_bytes(32));
        $_SESSION['csrf_token_time'] = time();
    }
    return $_SESSION['csrf_token'];
}

function csrfTokenVerify(string $token): bool
{
    if (session_status() === PHP_SESSION_NONE) {
        configureSecureSession();
    }
    $stored = $_SESSION['csrf_token'] ?? '';
    if (empty($stored) || empty($token)) return false;
    return hash_equals($stored, $token);
}

// ================================================================
// Rate Limiting (per IP, in DB)
// ================================================================

function rateLimitCheck(string $ip): bool
{
    $db  = getDB();
    $p   = DB_PREFIX;
    $now = date('Y-m-d H:i:s');

    try {
        $stmt = $db->prepare("SELECT upload_count, window_start FROM `{$p}rate_limits` WHERE ip = ?");
        $stmt->execute([$ip]);
        $row  = $stmt->fetch();

        if (!$row) {
            $db->prepare("INSERT IGNORE INTO `{$p}rate_limits` (ip, upload_count, window_start) VALUES (?, 1, ?)")
               ->execute([$ip, $now]);
            return true;
        }

        $elapsed = time() - strtotime($row['window_start']);

        if ($elapsed > RATE_LIMIT_WINDOW) {
            $db->prepare("UPDATE `{$p}rate_limits` SET upload_count=1, window_start=? WHERE ip=?")
               ->execute([$now, $ip]);
            return true;
        }

        if ((int)$row['upload_count'] >= RATE_LIMIT_MAX) {
            return false;
        }

        $db->prepare("UPDATE `{$p}rate_limits` SET upload_count = upload_count + 1 WHERE ip=?")
           ->execute([$ip]);
        return true;
    } catch (PDOException $e) {
        error_log('rateLimitCheck error: ' . $e->getMessage());
        return true; // Fail open doar daca DB e down, altfel intreaga aplicatia e blocata
    }
}

/**
 * Rate limit pentru autentificari admin (mai strict)
 * Max 5 incercari in 15 minute per IP
 */
function loginRateLimitCheck(string $ip): bool
{
    $db  = getDB();
    $p   = DB_PREFIX;
    $now = date('Y-m-d H:i:s');

    try {
        $stmt = $db->prepare("SELECT upload_count, window_start FROM `{$p}rate_limits` WHERE ip = ?");
        $stmt->execute(['login_' . $ip]);
        $row = $stmt->fetch();

        if (!$row) {
            $db->prepare("INSERT IGNORE INTO `{$p}rate_limits` (ip, upload_count, window_start) VALUES (?, 1, ?)")
               ->execute(['login_' . $ip, $now]);
            return true;
        }

        $elapsed = time() - strtotime($row['window_start']);

        if ($elapsed > 900) { // 15 minute
            $db->prepare("UPDATE `{$p}rate_limits` SET upload_count=1, window_start=? WHERE ip=?")
               ->execute([$now, 'login_' . $ip]);
            return true;
        }

        if ((int)$row['upload_count'] >= 5) {
            return false; // Blocat
        }

        $db->prepare("UPDATE `{$p}rate_limits` SET upload_count = upload_count + 1 WHERE ip=?")
           ->execute(['login_' . $ip]);
        return true;
    } catch (PDOException $e) {
        error_log('loginRateLimitCheck error: ' . $e->getMessage());
        return true;
    }
}

function loginRateLimitReset(string $ip): void
{
    try {
        $db = getDB(); $p = DB_PREFIX;
        $db->prepare("DELETE FROM `{$p}rate_limits` WHERE ip=?")->execute(['login_' . $ip]);
    } catch (PDOException $e) {}
}

// ================================================================
// Upload Rate Limiting (per IP + cookie, max 1 upload / 60 secunde)
// ================================================================

/**
 * Returneaza (sau creeaza) cookie-ul de tracking pentru rate-limit la upload.
 * Cookie-ul e HttpOnly, Secure, SameSite=Strict si dureaza 30 de zile.
 */
function getOrSetUploadCookie(): string
{
    $name = 'dt_uc';
    if (!empty($_COOKIE[$name]) && preg_match('/^[a-f0-9]{64}$/', $_COOKIE[$name])) {
        return $_COOKIE[$name];
    }
    $id = bin2hex(random_bytes(32));
    setcookie($name, $id, [
        'expires'  => time() + 86400 * 30,
        'path'     => '/',
        'secure'   => true,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    return $id;
}

/**
 * Verifica daca IP-ul sau cookie-ul a mai facut un upload in ultimul minut.
 * Returneaza true daca upload-ul e permis, false daca e blocat.
 *
 * Chei in tabel: 'up_' + IP (max 42 chars) si 'uc_' + md5(cookieId) (35 chars)
 * — ambele incap in VARCHAR(45).
 */
function rateLimitUpload(string $ip, string $cookieId): bool
{
    $db  = getDB();
    $p   = DB_PREFIX;
    $now = date('Y-m-d H:i:s');

    $ipKey     = 'up_' . $ip;
    $cookieKey = 'uc_' . md5($cookieId);

    try {
        $stmt = $db->prepare("SELECT window_start FROM `{$p}rate_limits` WHERE ip=?");

        // Verifica IP
        $stmt->execute([$ipKey]);
        $row = $stmt->fetch();
        if ($row && (time() - strtotime($row['window_start'])) < 60) {
            return false; // Blocat pe IP
        }

        // Verifica cookie
        $stmt->execute([$cookieKey]);
        $row = $stmt->fetch();
        if ($row && (time() - strtotime($row['window_start'])) < 60) {
            return false; // Blocat pe cookie
        }

        // Permite: actualizeaza timestamp-ul pentru IP si cookie
        $ins = "INSERT INTO `{$p}rate_limits` (ip, upload_count, window_start) VALUES (?,1,?)
                ON DUPLICATE KEY UPDATE upload_count=1, window_start=?";
        $db->prepare($ins)->execute([$ipKey, $now, $now]);
        $db->prepare($ins)->execute([$cookieKey, $now, $now]);

        return true;
    } catch (PDOException $e) {
        error_log('rateLimitUpload error: ' . $e->getMessage());
        return true; // Fail open daca DB e down
    }
}

// ================================================================
// Validare fisier (extensie + MIME + magic bytes)
// ================================================================

function validateUploadedFile(array $file): array
{
    $tmpPath  = $file['tmp_name'];
    $origName = $file['name'];

    // 1. Dimensiune
    if ($file['size'] > MAX_FILE_SIZE) {
        $maxMB = round(MAX_FILE_SIZE / 1024 / 1024);
        return ['ok' => false, 'error' => "Fisierul depaseste limita de {$maxMB} MB.", 'mime' => ''];
    }

    // 2. Upload legitim PHP
    if (!is_uploaded_file($tmpPath)) {
        return ['ok' => false, 'error' => 'Fisier invalid (nu e upload legitim).', 'mime' => ''];
    }

    // 3. Extensii (blocheaza double extensions: file.php.jpg)
    $origNameClean = basename($origName);
    $parts         = explode('.', $origNameClean);
    if (count($parts) < 2) {
        return ['ok' => false, 'error' => 'Fisierul trebuie sa aiba o extensie.', 'mime' => ''];
    }

    $dangerousExts = [
        'php', 'php2', 'php3', 'php4', 'php5', 'php6', 'php7', 'php8',
        'phtml', 'phar', 'shtml', 'shtm',
        'asp', 'aspx', 'ashx', 'asmx', 'axd',
        'jsp', 'jspx', 'jsf', 'jspf',
        'cgi', 'pl', 'py', 'pyc', 'pyo', 'rb',
        'sh', 'bash', 'zsh', 'ksh', 'fish',
        'bat', 'cmd', 'ps1', 'psm1', 'psd1', 'vbs', 'vbe', 'wsf', 'wsh',
        'exe', 'dll', 'so', 'dylib', 'msi', 'com', 'scr', 'hta',
        'jar', 'war', 'ear', 'class',
        'htaccess', 'htpasswd',
    ];

    foreach (array_slice($parts, 1) as $ext) {
        if (in_array(strtolower($ext), $dangerousExts, true)) {
            return ['ok' => false, 'error' => "Extensia '.{$ext}' nu este permisa.", 'mime' => ''];
        }
    }

    $ext = strtolower(end($parts));

    // 4. Whitelist extensii
    if (!in_array($ext, ALLOWED_EXTENSIONS, true)) {
        return ['ok' => false, 'error' => "Extensia '.{$ext}' nu este permisa.", 'mime' => ''];
    }

    // 5. MIME type real (din continut, nu din header HTTP)
    $finfo    = new finfo(FILEINFO_MIME_TYPE);
    $realMime = $finfo->file($tmpPath);

    if ($realMime === false || $realMime === '') {
        return ['ok' => false, 'error' => 'Nu s-a putut determina tipul fisierului.', 'mime' => ''];
    }

    // 6. Blocheaza MIME-uri periculoase (extins)
    $blockedMimes = array_merge(BLOCKED_MIME_PREFIXES, [
        'application/x-executable',
        'application/x-elf',
        'application/x-msdownload',
        'application/x-msdos-program',
        'application/x-dosexec',
        'application/x-sh',
        'application/x-shellscript',
        'application/x-csh',
        'text/x-php',
        'application/x-php',
        'application/x-httpd-php',
        'application/x-httpd-php-source',
        'text/html',
        'text/x-html',
        'application/xhtml+xml',
        'application/javascript',
        'text/javascript',
        'application/ecmascript',
        'text/ecmascript',
        'application/x-perl',
        'text/x-perl',
        'application/x-python',
        'text/x-python',
        'text/x-python-script',
        'application/x-ruby',
        'application/x-mach-binary',
        'application/x-java-applet',
        'application/java-archive',
        'application/x-jar',
        'application/x-asp',
        'application/x-aspx',
    ]);

    foreach ($blockedMimes as $blocked) {
        if (stripos($realMime, $blocked) === 0 || strcasecmp($realMime, $blocked) === 0) {
            return ['ok' => false, 'error' => "Tipul de fisier '{$realMime}' nu este permis.", 'mime' => $realMime];
        }
    }

    // 7. Magic bytes (primii 16 octeti)
    $magicResult = checkMagicBytes($tmpPath);
    if ($magicResult !== null) {
        return ['ok' => false, 'error' => $magicResult, 'mime' => $realMime];
    }

    // 8. Scan continut pentru cod PHP/script ascuns (pentru imagini, documente, arhive)
    // Fisierele binare (imagini) primesc un scan mai ingust - doar PHP tags - pentru a evita false positives
    $binaryImageExts = ['jpg','jpeg','png','gif','bmp','webp','tiff','tif','ico','avif','heic','heif'];
    $textDocExts     = ['pdf','zip','docx','xlsx','pptx','odt','ods','odp','rtf','svg','xml'];
    if (in_array($ext, $binaryImageExts, true)) {
        if (fileContainsDangerousCode($tmpPath, true)) {
            return ['ok' => false, 'error' => 'Fisierul contine cod PHP ascuns in imagine. Nu este permis.', 'mime' => $realMime];
        }
    } elseif (in_array($ext, $textDocExts, true)) {
        if (fileContainsDangerousCode($tmpPath, false)) {
            return ['ok' => false, 'error' => 'Fisierul contine cod suspect (PHP/script tags detectate).', 'mime' => $realMime];
        }
    }

    return ['ok' => true, 'error' => null, 'mime' => $realMime];
}

function checkMagicBytes(string $path): ?string
{
    $handle = fopen($path, 'rb');
    if (!$handle) return 'Nu s-a putut citi fisierul.';
    $header = fread($handle, 16);
    fclose($handle);

    if ($header === false || strlen($header) === 0) return null;

    $bytes = array_values(unpack('C*', $header));

    // Windows PE Executable (MZ): 4D 5A
    if (count($bytes) >= 2 && $bytes[0] === 0x4D && $bytes[1] === 0x5A) {
        return 'Executabil Windows detectat (.exe/.dll). Nu este permis.';
    }
    // Linux ELF: 7F 45 4C 46
    if (count($bytes) >= 4 &&
        $bytes[0]===0x7F && $bytes[1]===0x45 && $bytes[2]===0x4C && $bytes[3]===0x46) {
        return 'Executabil Linux (ELF) detectat. Nu este permis.';
    }
    // Mach-O (macOS): CE/CF FA ED FE sau FE ED FA CE/CF
    if (count($bytes) >= 4 &&
        (($bytes[0]===0xCE||$bytes[0]===0xCF) && $bytes[1]===0xFA && $bytes[2]===0xED && $bytes[3]===0xFE)) {
        return 'Executabil macOS detectat. Nu este permis.';
    }
    if (count($bytes) >= 4 &&
        ($bytes[0]===0xFE && $bytes[1]===0xED && $bytes[2]===0xFA && ($bytes[3]===0xCE||$bytes[3]===0xCF))) {
        return 'Executabil macOS detectat. Nu este permis.';
    }
    // Script shell: #!
    if (count($bytes) >= 2 && $bytes[0]===0x23 && $bytes[1]===0x21) {
        return 'Script shell detectat (#!/...). Nu este permis.';
    }
    // Java class: CA FE BA BE
    if (count($bytes) >= 4 &&
        $bytes[0]===0xCA && $bytes[1]===0xFE && $bytes[2]===0xBA && $bytes[3]===0xBE) {
        return 'Java class/JAR detectat. Nu este permis.';
    }
    // PHP open tag la inceput
    $headerStr = substr($header, 0, 6);
    if (stripos($headerStr, '<?') !== false) {
        return 'Cod PHP detectat la inceputul fisierului. Nu este permis.';
    }
    // HTML la inceput
    $hLower = strtolower(substr($header, 0, 10));
    if (str_starts_with($hLower, '<html') ||
        str_starts_with($hLower, '<!doctype') ||
        str_starts_with($hLower, '<script')) {
        return 'Fisierele HTML/script nu sunt permise.';
    }

    return null;
}

function fileContainsDangerousCode(string $path, bool $isBinaryImage = false): bool
{
    $handle = fopen($path, 'rb');
    if (!$handle) return false;

    // Citeste primii si ultimii 4KB (webshells sunt adesea ascunse la capete)
    $start = fread($handle, 4096);
    @fseek($handle, -4096, SEEK_END);
    $end = fread($handle, 4096);
    fclose($handle);

    $content = ($start ?? '') . ($end ?? '');

    if ($isBinaryImage) {
        // Pentru fisiere binare (imagini) verificam DOAR tag-urile PHP
        // Alte pattern-uri (eval, assert, base64_decode etc.) apar aleator in date binare => false positive
        $patterns = ['<?php', '<?='];
    } else {
        // Pentru fisiere text/documente verificam tot setul de pattern-uri periculoase
        $patterns = [
            '<?php', '<?=', '<%', '%>',
            '<script', '</script',
            'eval(', 'base64_decode(',
            'system(', 'exec(', 'passthru(', 'shell_exec(',
            'proc_open(', 'popen(', 'assert(',
            'create_function(',
            'call_user_func(',
        ];
    }

    foreach ($patterns as $pattern) {
        if (stripos($content, $pattern) !== false) {
            return true;
        }
    }
    return false;
}

// ================================================================
// Sanitizare input
// ================================================================

function sanitizeFilename(string $name): string
{
    $name = basename($name);
    // Permite: alfanumerice, spatii, cratime, puncte, underscore, diacritice
    $name = preg_replace('/[^\w\s\-\.]/u', '', $name);
    $name = preg_replace('/\.{2,}/', '.', $name); // blocheaza ../
    $name = preg_replace('/\s+/', ' ', $name);
    $name = trim($name, '. ');
    // Lungime maxima
    if (strlen($name) > 200) {
        $ext  = pathinfo($name, PATHINFO_EXTENSION);
        $base = pathinfo($name, PATHINFO_FILENAME);
        $name = substr($base, 0, 195) . ($ext ? '.' . $ext : '');
    }
    return $name ?: 'fisier';
}

function sanitizeString(string $input, int $maxLen = 500): string
{
    $input = trim(substr($input, 0, $maxLen));
    // Strip null bytes
    $input = str_replace("\0", '', $input);
    return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5 | ENT_SUBSTITUTE, 'UTF-8');
}

// ================================================================
// Generare token securizat
// ================================================================

function generateToken(): string
{
    return bin2hex(random_bytes(32)); // 64 hex chars, 256 bits de entropie
}

// ================================================================
// IP client
// ================================================================

function getClientIP(): string
{
    // Folosim exclusiv REMOTE_ADDR — nu poate fi falsificat de client
    // X-Forwarded-For poate fi falsificat si NU trebuie folosit pentru securitate
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    // Validare format IP (IPv4 + IPv6)
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
}

// ================================================================
// Security Headers
// ================================================================

function sendSecurityHeaders(): void
{
    // Nu afisa versiunea PHP
    header_remove('X-Powered-By');

    // Previne MIME sniffing
    header('X-Content-Type-Options: nosniff');

    // Previne clickjacking
    header('X-Frame-Options: DENY');

    // XSS Protection (legacy, dar util pe browsere vechi)
    header('X-XSS-Protection: 1; mode=block');

    // Referrer: trimite doar originea la cross-site
    header('Referrer-Policy: strict-origin-when-cross-origin');

    // CSP strict:
    // - Fara inline scripts (reduce XSS) - Google Fonts e externat
    // - Fara eval()
    // - Imagini si date: permise (pentru emoji / inline data)
    // Nota: Google Fonts sunt in <head> ca stylesheet extern, permis de style-src
    header("Content-Security-Policy: " .
        "default-src 'none'; " .
        "script-src 'self' 'unsafe-inline'; " .   // unsafe-inline necesar pentru JS inline
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " .
        "font-src 'self' https://fonts.gstatic.com; " .
        "img-src 'self' data:; " .
        "connect-src 'self'; " .
        "form-action 'self'; " .
        "frame-ancestors 'none'; " .
        "base-uri 'self';"
    );

    // Restrictii permisiuni browser
    header('Permissions-Policy: ' .
        'geolocation=(), microphone=(), camera=(), ' .
        'payment=(), usb=(), magnetometer=(), gyroscope=(), ' .
        'fullscreen=(self), clipboard-write=(self)'
    );

    // HSTS: forteaza HTTPS pentru 1 an (nu include subdomenii pentru siguranta)
    header('Strict-Transport-Security: max-age=31536000');

    // Previne cache pe pagini sensibile
    if (defined('NO_CACHE') && NO_CACHE) {
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
    }
}

/**
 * Headers speciali pentru paginile de admin (mai restrictivi)
 */
function sendAdminSecurityHeaders(): void
{
    sendSecurityHeaders();
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('X-Robots-Tag: noindex, nofollow, noarchive');
}
