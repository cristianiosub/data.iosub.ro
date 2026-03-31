<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/security.php';
require_once __DIR__ . '/GoogleDrive.php';
configureSecureSession();
sendSecurityHeaders();

function fmtB(int $b): string {
    if($b<1024)return $b.' B';
    if($b<1<<20)return round($b/1024,1).' KB';
    if($b<1<<30)return round($b/1048576,1).' MB';
    return round($b/1073741824,2).' GB';
}

function pageErr(string $msg, int $code=404): never {
    http_response_code($code);
    $app=APP_NAME; $base=BASE_URL;
    echo "<!DOCTYPE html><html lang='ro'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
    <title>Eroare &mdash; {$app}</title>
    <link href='https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap' rel='stylesheet'>
    <style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:Inter,-apple-system,sans-serif;background:#f8fafc;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}.box{background:#fff;border:1px solid #e2e8f0;border-radius:20px;padding:40px 32px;text-align:center;max-width:380px;box-shadow:0 8px 32px rgba(0,0,0,.07)}.ico{font-size:48px;margin-bottom:16px}h2{font-size:18px;font-weight:700;color:#0f172a;margin-bottom:8px}p{color:#64748b;font-size:14px;line-height:1.6}a{display:inline-block;margin-top:20px;color:#6366f1;font-size:14px;font-weight:500;text-decoration:none}</style>
    </head><body><div class='box'><div class='ico'>❌</div><h2>Fișier indisponibil</h2><p>".htmlspecialchars($msg)."</p><a href='{$base}'>← Trimite un fișier nou</a></div></body></html>";
    exit;
}

$token = trim($_GET['token'] ?? '');
if (!preg_match('/^[a-f0-9]{64}$/', $token)) pageErr('Link invalid.', 400);

$db = getDB(); $p = DB_PREFIX;
$stmt = $db->prepare("SELECT * FROM `{$p}transfers` WHERE token=? AND deleted_at IS NULL LIMIT 1");
$stmt->execute([$token]); $transfer = $stmt->fetch();
if (!$transfer) pageErr('Fișierul nu a fost găsit sau a fost șters.', 404);

if (strtotime($transfer['expires_at']) < time()) {
    // Sterge fisiere fizice
    $fStmt = $db->prepare("SELECT stored_name FROM `{$p}files` WHERE transfer_id=?");
    $fStmt->execute([$transfer['id']]);
    foreach ($fStmt->fetchAll() as $f) { @unlink(UPLOAD_DIR.'/'.$f['stored_name']); }
    $db->prepare("UPDATE `{$p}transfers` SET deleted_at=NOW() WHERE token=?")->execute([$token]);
    pageErr('Acest fișier a expirat și a fost șters automat.', 410);
}

$maxDl = (int)$transfer['max_downloads'];
$dlCnt = (int)$transfer['download_count'];
if ($maxDl > 0 && $dlCnt >= $maxDl) pageErr('Numărul maxim de descărcări a fost atins.', 410);

// Incarca fisierele transferului
$fStmt = $db->prepare("SELECT * FROM `{$p}files` WHERE transfer_id=? ORDER BY id ASC");
$fStmt->execute([$transfer['id']]);
$fileRows = $fStmt->fetchAll();
if (empty($fileRows)) pageErr('Nu există fișiere în acest transfer.', 404);

$isSingle = count($fileRows) === 1;

// Verifica existenta fisierelor
foreach ($fileRows as $fr) {
    if (!preg_match('/^[a-f0-9]{32}$/', $fr['stored_name'])) pageErr('Date incorecte in baza de date.', 500);
    // Daca fisierul e pe Google Drive, nu verificam disk-ul local
    if (empty($fr['drive_file_id']) && !file_exists(UPLOAD_DIR.'/'.$fr['stored_name'])) {
        pageErr('Unul sau mai multe fișiere lipsesc de pe server.', 404);
    }
}

$hasPass = !empty($transfer['password_hash']);
$passOk  = false; $passErr = ''; $csrf = csrfTokenGenerate();
$clientIP = getClientIP();
$clientUA = $_SERVER['HTTP_USER_AGENT'] ?? '';

if ($hasPass) {
    if ($_SERVER['REQUEST_METHOD']==='POST') {
        if (!csrfTokenVerify($_POST['csrf_token']??'')) { $passErr='Token CSRF invalid.'; }
        else {
            if (password_verify($_POST['password']??'', $transfer['password_hash'])) {
                $passOk=true; $_SESSION['auth_'.$token]=true;
                unset($_SESSION['csrf_token']); $csrf=csrfTokenGenerate();
            } else { sleep(1); $passErr='Parolă incorectă.'; }
        }
    }
    if (isset($_SESSION['auth_'.$token])) $passOk=true;
} else { $passOk=true; }

/**
 * Verifica path traversal: stored_name trebuie sa fie strict in UPLOAD_DIR
 * stored_name este generat de noi (hex), deci nu poate contine '/', dar verificam oricum
 */
function safeFilePath(string $storedName): string|false
{
    // stored_name trebuie sa fie exact 32 caractere hex (generat de noi cu bin2hex(random_bytes(16)))
    if (!preg_match('/^[a-f0-9]{32}$/', $storedName)) return false;
    $realDir  = realpath(UPLOAD_DIR);
    if ($realDir === false) return false;
    $fullPath = $realDir . DIRECTORY_SEPARATOR . $storedName;
    // realpath verifica ca fisierul exista si nu iese din director
    $realPath = realpath($fullPath);
    if ($realPath === false) return false;
    if (strpos($realPath, $realDir . DIRECTORY_SEPARATOR) !== 0) return false;
    return $realPath;
}

/**
 * Genereaza un Content-Disposition header sigur (RFC 5987)
 */
function contentDispositionHeader(string $filename): string
{
    // ASCII fallback + UTF-8 encoded filename
    $ascii   = preg_replace('/[^\x20-\x7E]/', '_', $filename);
    $encoded = rawurlencode($filename);
    return "attachment; filename=\"{$ascii}\"; filename*=UTF-8''{$encoded}";
}

// ── Descărcare fișier individual ─────────────────────────────────────────
if ($passOk && isset($_GET['dl']) && preg_match('/^\d+$/', $_GET['dl'])) {
    $fileId = (int)$_GET['dl'];
    $fr = null;
    foreach ($fileRows as $r) { if ((int)$r['id']==$fileId) { $fr=$r; break; } }
    if (!$fr) pageErr('Fișier negăsit.', 404);

    $db->prepare("UPDATE `{$p}transfers` SET download_count=download_count+1 WHERE token=?")->execute([$token]);
    if ($maxDl>0 && ($dlCnt+1)>=$maxDl)
        $db->prepare("UPDATE `{$p}transfers` SET deleted_at=NOW() WHERE token=?")->execute([$token]);

    logEvent((int)$transfer['id'], 'download', $clientIP, $clientUA);

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: ' . contentDispositionHeader($fr['original_name']));
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('X-Content-Type-Options: nosniff');
    header('Content-Security-Policy: default-src \'none\'');

    if (ob_get_level()) ob_end_clean();

    if (GDRIVE_ENABLED && !empty($fr['drive_file_id'])) {
        // ── Stream din Google Drive ─────────────────────────────────
        try {
            $gdrive = new GoogleDrive(GDRIVE_SA_KEY_FILE);
            $gdrive->streamFile($fr['drive_file_id']);
        } catch (RuntimeException $e) {
            error_log('Drive stream error: ' . $e->getMessage());
            // Nu putem trimite JSON acum (headerele sunt trimise), afisam text
            http_response_code(500);
            echo 'Eroare la descarcarea din cloud.';
        }
    } else {
        // ── Stream de pe disk local (fallback) ─────────────────────
        $filePath = safeFilePath($fr['stored_name']);
        if ($filePath === false || !file_exists($filePath)) pageErr('Fișierul nu mai există pe server.', 404);
        header('Content-Length: ' . filesize($filePath));
        $h = fopen($filePath, 'rb');
        if ($h) { while (!feof($h)) { echo fread($h, 65536); flush(); } fclose($h); }
    }
    exit;
}

// ── Descărcare ZIP (toate fișierele) ─────────────────────────────────────
if ($passOk && ($_GET['zip']??'')==='1') {
    if (!class_exists('ZipArchive')) pageErr('ZIP nu este disponibil pe acest server.', 500);

    $tmpZip = tempnam(sys_get_temp_dir(), 'dt_zip_');
    if ($tmpZip === false) pageErr('Nu s-a putut crea fisier temporar.', 500);

    $zip = new ZipArchive();
    if ($zip->open($tmpZip, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        @unlink($tmpZip);
        pageErr('Nu s-a putut crea arhiva ZIP.', 500);
    }

    // Instantiem Drive o singura data, refolosim pentru toate fisierele
    $gdriveZip = null;
    if (GDRIVE_ENABLED) {
        try { $gdriveZip = new GoogleDrive(GDRIVE_SA_KEY_FILE); } catch (RuntimeException) {}
    }

    foreach ($fileRows as $fr) {
        $safeName = basename($fr['original_name']);

        if (GDRIVE_ENABLED && $gdriveZip !== null && !empty($fr['drive_file_id'])) {
            // Descarca fisierul din Drive intr-un temp file si adauga in ZIP
            $tmpItem = tempnam(sys_get_temp_dir(), 'dt_item_');
            if ($tmpItem === false) continue;
            try {
                ob_start();
                $gdriveZip->streamFile($fr['drive_file_id']);
                $content = ob_get_clean();
                file_put_contents($tmpItem, $content);
                $zip->addFile($tmpItem, $safeName);
                // Tinem evidenta tmp files pentru stergere dupa close()
                $tmpItems[] = $tmpItem;
            } catch (RuntimeException $e) {
                ob_end_clean();
                @unlink($tmpItem);
                error_log('Drive ZIP item error: ' . $e->getMessage());
            }
        } else {
            // Fallback disk local
            $realPath = safeFilePath($fr['stored_name']);
            if ($realPath !== false && file_exists($realPath)) {
                $zip->addFile($realPath, $safeName);
            }
        }
    }
    $zip->close();

    // Sterge temp items dupa ce ZIP-ul e inchis (ZipArchive face referinta la ele pana la close)
    foreach ($tmpItems ?? [] as $ti) { @unlink($ti); }

    $db->prepare("UPDATE `{$p}transfers` SET download_count=download_count+1 WHERE token=?")->execute([$token]);
    if ($maxDl>0 && ($dlCnt+1)>=$maxDl)
        $db->prepare("UPDATE `{$p}transfers` SET deleted_at=NOW() WHERE token=?")->execute([$token]);

    logEvent((int)$transfer['id'], 'download', $clientIP, $clientUA);

    $zipName = preg_replace('/[^a-zA-Z0-9_\-]/', '_', $transfer['bundle_name']).'_'.date('Ymd').'.zip';
    header('Content-Type: application/zip');
    header('Content-Disposition: ' . contentDispositionHeader($zipName));
    header('Content-Length: ' . filesize($tmpZip));
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('X-Content-Type-Options: nosniff');

    if (ob_get_level()) ob_end_clean();
    readfile($tmpZip);
    @unlink($tmpZip);
    exit;
}

// ── Pagina HTML ───────────────────────────────────────────────────────────
$bundleName = htmlspecialchars($transfer['bundle_name']);
$totalSize  = fmtB((int)$transfer['total_size']);
$created    = date('d.m.Y H:i', strtotime($transfer['created_at']));
$expires    = date('d.m.Y H:i', strtotime($transfer['expires_at']));
$daysLeft   = max(0,(int)ceil((strtotime($transfer['expires_at'])-time())/86400));
$msg        = $transfer['message'] ? htmlspecialchars($transfer['message']) : null;
$fileCount  = count($fileRows);
?>
<!DOCTYPE html>
<html lang="ro">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Descarcă fișier<?= $fileCount>1?'e':'' ?> &mdash; <?= htmlspecialchars(APP_NAME) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#f8fafc;--surface:#fff;--border:#e2e8f0;--text:#0f172a;--t2:#475569;--t3:#94a3b8;--accent:#6366f1;--a2:#8b5cf6;--success:#10b981;--err:#ef4444;--shadow-lg:0 8px 32px rgba(0,0,0,.08),0 2px 8px rgba(0,0,0,.04)}
body{font-family:'Inter',-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:32px 16px;-webkit-font-smoothing:antialiased}
.logo{text-align:center;margin-bottom:24px}
.logo-icon{width:48px;height:48px;background:linear-gradient(135deg,var(--accent),var(--a2));border-radius:14px;display:inline-flex;align-items:center;justify-content:center;font-size:22px;margin-bottom:10px;box-shadow:0 4px 14px rgba(99,102,241,.22)}
.logo h1{font-size:18px;font-weight:700;letter-spacing:-.3px}
.card{width:100%;max-width:480px;background:var(--surface);border:1px solid var(--border);border-radius:20px;padding:28px;box-shadow:var(--shadow-lg)}
.bundle-header{background:var(--bg);border:1px solid var(--border);border-radius:14px;padding:16px 18px;margin-bottom:18px}
.bh-top{display:flex;align-items:center;gap:12px;margin-bottom:10px}
.bh-ico{font-size:32px;flex-shrink:0}
.bh-info{flex:1;min-width:0}
.bh-name{font-size:15px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bh-meta{display:flex;gap:10px;flex-wrap:wrap;margin-top:4px}
.bh-tag{font-size:11px;color:var(--t3)}
/* Lista fisiere */
.files-list{border:1px solid var(--border);border-radius:12px;overflow:hidden;margin-bottom:18px}
.file-row{display:flex;align-items:center;gap:10px;padding:11px 14px;border-top:1px solid var(--border);transition:background .15s}
.file-row:first-child{border-top:none}
.file-row:hover{background:rgba(99,102,241,.03)}
.fr-ico{font-size:18px;flex-shrink:0}
.fr-info{flex:1;min-width:0}
.fr-name{font-size:13px;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.fr-size{font-size:11px;color:var(--t3);margin-top:1px}
.fr-dl{display:inline-flex;align-items:center;gap:4px;background:rgba(99,102,241,.08);border:1px solid rgba(99,102,241,.2);border-radius:6px;padding:4px 10px;font-size:11px;font-weight:600;color:var(--accent);text-decoration:none;white-space:nowrap;transition:all .15s}
.fr-dl:hover{background:var(--accent);color:#fff;border-color:var(--accent)}
.msg-box{background:linear-gradient(135deg,rgba(99,102,241,.06),rgba(139,92,246,.04));border:1px solid rgba(99,102,241,.18);border-radius:12px;padding:13px 15px;font-size:13px;color:var(--t2);line-height:1.5;margin-bottom:18px}
/* Password form */
.pw-form label{display:block;font-size:12px;font-weight:600;color:var(--t2);margin-bottom:6px}
.pw-wrap{position:relative;margin-bottom:0}
.pw-wrap input{width:100%;border:1.5px solid var(--border);border-radius:10px;padding:10px 40px 10px 14px;font-size:14px;color:var(--text);outline:none;transition:border-color .2s,box-shadow .2s;font-family:inherit;background:#fafbfc}
.pw-wrap input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(99,102,241,.1);background:#fff}
.pw-eye{position:absolute;right:11px;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--t3);cursor:pointer;font-size:15px;padding:0}
.err-msg{background:#fff5f5;border:1px solid #fecaca;border-radius:8px;padding:10px 13px;color:#991b1b;font-size:13px;margin-top:10px}
/* Buttons */
.btn{display:flex;align-items:center;justify-content:center;gap:7px;width:100%;padding:13px;background:linear-gradient(135deg,var(--accent),var(--a2));border:none;border-radius:12px;color:#fff;font-size:14px;font-weight:600;cursor:pointer;text-decoration:none;font-family:inherit;transition:opacity .2s;box-shadow:0 4px 14px rgba(99,102,241,.28);margin-bottom:8px}
.btn:hover{opacity:.91}
.btn-outline{background:var(--surface);border:1.5px solid var(--border);color:var(--t2);box-shadow:none}
.btn-outline:hover{border-color:var(--accent);color:var(--accent);opacity:1}
.exp{margin-top:12px;text-align:center;font-size:12px;color:var(--t3)}
.exp.warn{color:#b45309}
.back{display:block;text-align:center;margin-top:18px;font-size:13px;color:var(--t3);text-decoration:none;transition:color .2s}
.back:hover{color:var(--accent)}
</style>
</head>
<body>
<div class="logo">
  <div class="logo-icon">🔒</div>
  <h1><?= htmlspecialchars(APP_NAME) ?></h1>
</div>

<div class="card">
  <div class="bundle-header">
    <div class="bh-top">
      <div class="bh-ico"><?= $fileCount>1?'📦':'📄' ?></div>
      <div class="bh-info">
        <div class="bh-name" title="<?= $bundleName ?>"><?= $bundleName ?></div>
        <div class="bh-meta">
          <span class="bh-tag">📦 <?= $totalSize ?></span>
          <span class="bh-tag">📅 <?= $created ?></span>
          <?php if($fileCount>1): ?><span class="bh-tag">🗂 <?= $fileCount ?> fișiere</span><?php endif; ?>
          <?php if($hasPass): ?><span class="bh-tag">🔑 Protejat</span><?php endif; ?>
        </div>
      </div>
    </div>
  </div>

  <?php if($msg): ?>
  <div class="msg-box">💬 <?= $msg ?></div>
  <?php endif; ?>

  <?php if($hasPass && !$passOk): ?>
  <form class="pw-form" method="POST">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
    <label>Introdu parola pentru a descărca</label>
    <div class="pw-wrap">
      <input type="password" name="password" placeholder="Parola transferului" autofocus required>
      <button type="button" class="pw-eye" onclick="var i=this.previousElementSibling;i.type=i.type==='password'?'text':'password';this.textContent=i.type==='password'?'👁':'🙈'">👁</button>
    </div>
    <?php if($passErr): ?><div class="err-msg">⚠️ <?= htmlspecialchars($passErr) ?></div><?php endif; ?>
    <button type="submit" class="btn" style="margin-top:14px">🔓 Verifică parola</button>
  </form>
  <?php else: ?>

  <?php if($fileCount>1): ?>
  <!-- Lista fișiere individuale -->
  <div class="files-list">
    <?php
    $fileIcons=['pdf'=>'📑','doc'=>'📝','docx'=>'📝','xls'=>'📊','xlsx'=>'📊',
      'ppt'=>'📊','pptx'=>'📊','txt'=>'📄','csv'=>'📊',
      'jpg'=>'🖼','jpeg'=>'🖼','png'=>'🖼','gif'=>'🖼','webp'=>'🖼',
      'mp4'=>'🎬','avi'=>'🎬','mov'=>'🎬','mkv'=>'🎬',
      'mp3'=>'🎵','wav'=>'🎵','flac'=>'🎵',
      'zip'=>'📦','rar'=>'📦','7z'=>'📦','gz'=>'📦'];
    foreach($fileRows as $fr):
      $ext=strtolower(pathinfo($fr['original_name'],PATHINFO_EXTENSION));
      $fi=$fileIcons[$ext]??'📄';
      $dlLink=BASE_URL.'/download.php?token='.urlencode($token).'&dl='.$fr['id'];
    ?>
    <div class="file-row">
      <div class="fr-ico"><?= $fi ?></div>
      <div class="fr-info">
        <div class="fr-name" title="<?= htmlspecialchars($fr['original_name']) ?>"><?= htmlspecialchars($fr['original_name']) ?></div>
        <div class="fr-size"><?= fmtB((int)$fr['file_size']) ?></div>
      </div>
      <a href="<?= htmlspecialchars($dlLink) ?>" class="fr-dl">⬇ Descarcă</a>
    </div>
    <?php endforeach; ?>
  </div>
  <!-- ZIP toate -->
  <a href="<?= htmlspecialchars(BASE_URL.'/download.php?token='.urlencode($token).'&zip=1') ?>" class="btn">
    📦 Descarcă toate ca ZIP
  </a>
  <?php else: ?>
  <a href="<?= htmlspecialchars(BASE_URL.'/download.php?token='.urlencode($token).'&dl='.$fileRows[0]['id']) ?>" class="btn">
    ⬇️ Descarcă fișierul
  </a>
  <?php endif; ?>

  <?php endif; ?>

  <div class="exp <?= $daysLeft<=1?'warn':'' ?>">
    <?php if($daysLeft===0): ?>⚠️ Fișierul expiră astăzi!
    <?php elseif($daysLeft<=3): ?>⚠️ Expiră în <?= $daysLeft ?> <?= $daysLeft===1?'zi':'zile' ?>!
    <?php else: ?>⏳ Disponibil până la <?= $expires ?> (<?= $daysLeft ?> zile)<?php endif; ?>
  </div>
</div>

<a href="<?= BASE_URL ?>" class="back">← Trimite un fișier nou</a>
</body>
</html>
