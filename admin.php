<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/security.php';
require_once __DIR__ . '/GoogleDrive.php';
configureSecureSession();
sendAdminSecurityHeaders();
$p = DB_PREFIX;

// ── Logout ────────────────────────────────────────────────────────────────
if (isset($_POST['logout'])) {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $cp = session_get_cookie_params();
        setcookie(session_name(), '', time()-42000, $cp['path'], $cp['domain'], $cp['secure'], $cp['httponly']);
    }
    session_destroy();
    header('Location: admin.php'); exit;
}

// ── Sesiune expirata ──────────────────────────────────────────────────────
if (isset($_SESSION['admin_id'])) {
    // Timeout inactivitate: 2 ore
    if ((time() - ($_SESSION['admin_login_time'] ?? 0)) > 7200) {
        session_destroy();
        header('Location: admin.php?expired=1'); exit;
    }
    // Timeout absolut: 8 ore de la autentificare
    if ((time() - ($_SESSION['admin_absolute_start'] ?? 0)) > 28800) {
        session_destroy();
        header('Location: admin.php?expired=1'); exit;
    }
    // Verifica IP-ul sa nu se fi schimbat (session hijacking basic check)
    if (isset($_SESSION['admin_ip']) && $_SESSION['admin_ip'] !== getClientIP()) {
        session_destroy();
        header('Location: admin.php'); exit;
    }
    // Verifica User-Agent sa nu se fi schimbat
    $currentUaHash = md5($_SERVER['HTTP_USER_AGENT'] ?? '');
    if (isset($_SESSION['admin_ua']) && $_SESSION['admin_ua'] !== $currentUaHash) {
        session_destroy();
        header('Location: admin.php'); exit;
    }
    $_SESSION['admin_login_time'] = time(); // Refresh inactivity timestamp
}

// ── Autentificare ─────────────────────────────────────────────────────────
$loginErr = '';
if (!isset($_SESSION['admin_id'])) {
    if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['username'])) {
        $clientIP = getClientIP();
        if (!csrfTokenVerify($_POST['csrf_token']??'')) {
            $loginErr = 'Token CSRF invalid. Reîncarcă pagina.';
        } elseif (!loginRateLimitCheck($clientIP)) {
            $loginErr = 'Prea multe încercări eșuate. Încearcă din nou în 15 minute.';
            error_log("Admin login brute-force blocat: IP={$clientIP}");
        } else {
            $db = getDB();
            $stmt = $db->prepare("SELECT id,username,password_hash FROM `{$p}admins` WHERE username=? LIMIT 1");
            $stmt->execute([trim(substr($_POST['username'], 0, 100))]);
            $row = $stmt->fetch();
            if ($row && password_verify($_POST['password']??'', $row['password_hash'])) {
                loginRateLimitReset($clientIP);
                session_regenerate_id(true);
                $_SESSION['admin_id']             = $row['id'];
                $_SESSION['admin_user']           = $row['username'];
                $_SESSION['admin_login_time']     = time();
                $_SESSION['admin_absolute_start'] = time();
                $_SESSION['admin_ip']             = $clientIP;
                $_SESSION['admin_ua']             = md5($_SERVER['HTTP_USER_AGENT'] ?? '');
                $db->prepare("UPDATE `{$p}admins` SET last_login_at=NOW() WHERE id=?")->execute([$row['id']]);
                header('Location: admin.php'); exit;
            } else {
                sleep(1);
                $loginErr = 'Credențiale incorecte.';
            }
        }
    }
    $csrf = csrfTokenGenerate();
    ?>
<!DOCTYPE html>
<html lang="ro">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Login &mdash; <?= htmlspecialchars(APP_NAME) ?></title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--accent:#6366f1;--a2:#8b5cf6}
body{font-family:'Inter',-apple-system,sans-serif;background:#f8fafc;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;-webkit-font-smoothing:antialiased}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:20px;padding:36px 32px;width:100%;max-width:360px;box-shadow:0 8px 32px rgba(0,0,0,.08)}
.logo{text-align:center;margin-bottom:28px}
.logo-ico{width:48px;height:48px;background:linear-gradient(135deg,var(--accent),var(--a2));border-radius:14px;display:inline-flex;align-items:center;justify-content:center;font-size:22px;margin-bottom:10px;box-shadow:0 4px 14px rgba(99,102,241,.22)}
h1{font-size:18px;font-weight:700;color:#0f172a;text-align:center}
.sub{font-size:13px;color:#94a3b8;text-align:center;margin-top:3px}
label{display:block;font-size:12px;font-weight:600;color:#475569;margin-bottom:5px;margin-top:14px}
input{width:100%;border:1.5px solid #e2e8f0;border-radius:10px;padding:10px 14px;font-size:14px;color:#0f172a;outline:none;transition:border-color .2s,box-shadow .2s;font-family:inherit;background:#fafbfc}
input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(99,102,241,.1);background:#fff}
.pw-w{position:relative}.pw-w input{padding-right:40px}
.pw-e{position:absolute;right:11px;top:50%;transform:translateY(-50%);background:none;border:none;color:#94a3b8;cursor:pointer;font-size:15px;padding:0}
.err{background:#fff5f5;border:1px solid #fecaca;border-radius:8px;padding:10px 13px;color:#991b1b;font-size:13px;margin-top:12px}
.btn{width:100%;margin-top:20px;padding:12px;background:linear-gradient(135deg,var(--accent),var(--a2));border:none;border-radius:10px;color:#fff;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit;box-shadow:0 4px 14px rgba(99,102,241,.26);transition:opacity .2s}
.btn:hover{opacity:.91}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="logo-ico">🔒</div>
    <h1><?= htmlspecialchars(APP_NAME) ?></h1>
    <div class="sub">Panou de administrare</div>
  </div>
  <form method="POST">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
    <label>Username</label>
    <input type="text" name="username" autofocus required placeholder="admin" autocomplete="username">
    <label>Parolă</label>
    <div class="pw-w">
      <input type="password" name="password" required placeholder="••••••••" autocomplete="current-password" id="pwi">
      <button type="button" class="pw-e" onclick="var i=document.getElementById('pwi');i.type=i.type==='password'?'text':'password';this.textContent=i.type==='password'?'👁':'🙈'">👁</button>
    </div>
    <?php if(isset($_GET['expired'])): ?><div class="err">⏱ Sesiunea a expirat. Te rog autentifică-te din nou.</div><?php endif; ?>
    <?php if($loginErr): ?><div class="err">⚠️ <?= htmlspecialchars($loginErr) ?></div><?php endif; ?>
    <button type="submit" class="btn">Intră în admin →</button>
  </form>
</div>
</body>
</html>
    <?php exit;
}

// ── Admin autentificat ─────────────────────────────────────────────────────
$db = getDB();
$csrf = csrfTokenGenerate();

// ── Schimbare parola ──────────────────────────────────────────────────────
$pwMsg = ''; $pwErr = '';
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['change_pw'])) {
    if (!csrfTokenVerify($_POST['csrf_token']??'')) { $pwErr='Token CSRF invalid.'; }
    else {
        $oldPw  = $_POST['old_password'] ?? '';
        $newPw  = $_POST['new_password'] ?? '';
        $confPw = $_POST['confirm_password'] ?? '';
        $stmt = $db->prepare("SELECT password_hash FROM `{$p}admins` WHERE id=? LIMIT 1");
        $stmt->execute([$_SESSION['admin_id']]); $adminRow = $stmt->fetch();
        if (!$adminRow || !password_verify($oldPw, $adminRow['password_hash'])) {
            $pwErr = 'Parola curentă este incorectă.';
        } elseif (strlen($newPw) < 8) {
            $pwErr = 'Parola nouă trebuie să aibă minim 8 caractere.';
        } elseif ($newPw !== $confPw) {
            $pwErr = 'Parolele noi nu coincid.';
        } else {
            $hash = password_hash($newPw, PASSWORD_BCRYPT, ['cost'=>12]);
            $db->prepare("UPDATE `{$p}admins` SET password_hash=? WHERE id=?")->execute([$hash, $_SESSION['admin_id']]);
            $pwMsg = 'Parola a fost schimbată cu succes!';
        }
    }
}

// ── Actiune: stergere transfer ────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['del_token'])) {
    if (csrfTokenVerify($_POST['csrf_token']??'') && preg_match('/^[a-f0-9]{64}$/',$_POST['del_token'])) {
        $r=$db->prepare("SELECT id FROM `{$p}transfers` WHERE token=? LIMIT 1");
        $r->execute([$_POST['del_token']]); $trow=$r->fetch();
        if($trow){
            $tid=(int)$trow['id'];
            $fs=$db->prepare("SELECT stored_name, drive_file_id FROM `{$p}files` WHERE transfer_id=?");
            $fs->execute([$tid]);
            $gdrive = null;
            if (GDRIVE_ENABLED) {
                try { $gdrive = new GoogleDrive(GDRIVE_SA_KEY_FILE); } catch (RuntimeException) {}
            }
            foreach($fs->fetchAll() as $f){
                if (GDRIVE_ENABLED && $gdrive !== null && !empty($f['drive_file_id'])) {
                    try { $gdrive->deleteFile($f['drive_file_id']); } catch (RuntimeException) {}
                } else {
                    @unlink(UPLOAD_DIR.'/'.$f['stored_name']);
                }
            }
            $db->prepare("UPDATE `{$p}transfers` SET deleted_at=NOW() WHERE token=?")->execute([$_POST['del_token']]);
        }
    }
    header('Location: admin.php'); exit;
}

// ── Actiune: cleanup ──────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['cleanup'])) {
    if (csrfTokenVerify($_POST['csrf_token']??'')) {
        $expT=$db->query("SELECT id FROM `{$p}transfers` WHERE expires_at<NOW() AND deleted_at IS NULL")->fetchAll();
        $n=0;
        $gdrive = null;
        if (GDRIVE_ENABLED) {
            try { $gdrive = new GoogleDrive(GDRIVE_SA_KEY_FILE); } catch (RuntimeException) {}
        }
        foreach($expT as $trow){
            $tid=(int)$trow['id'];
            $fs=$db->prepare("SELECT stored_name, drive_file_id FROM `{$p}files` WHERE transfer_id=?");
            $fs->execute([$tid]);
            foreach($fs->fetchAll() as $f){
                if (GDRIVE_ENABLED && $gdrive !== null && !empty($f['drive_file_id'])) {
                    try { $gdrive->deleteFile($f['drive_file_id']); } catch (RuntimeException) {}
                } else {
                    @unlink(UPLOAD_DIR.'/'.$f['stored_name']);
                }
                $n++;
            }
            $db->prepare("UPDATE `{$p}transfers` SET deleted_at=NOW() WHERE id=?")->execute([$tid]);
        }
        $_SESSION['adm_msg']="✅ $n fișiere expirate șterse.";
    }
    header('Location: admin.php'); exit;
}

// ── Statistici ────────────────────────────────────────────────────────────
$total   = (int)$db->query("SELECT COUNT(*) FROM `{$p}transfers` WHERE deleted_at IS NULL")->fetchColumn();
$expired = (int)$db->query("SELECT COUNT(*) FROM `{$p}transfers` WHERE expires_at<NOW() AND deleted_at IS NULL")->fetchColumn();
$size    = (int)$db->query("SELECT COALESCE(SUM(total_size),0) FROM `{$p}transfers` WHERE deleted_at IS NULL")->fetchColumn();
$dls     = (int)$db->query("SELECT COALESCE(SUM(download_count),0) FROM `{$p}transfers`")->fetchColumn();
$totalFiles = (int)$db->query("SELECT COUNT(*) FROM `{$p}files`")->fetchColumn();

function fmtB(int $b):string{if($b<1024)return $b.' B';if($b<1<<20)return round($b/1024,1).' KB';if($b<1<<30)return round($b/1048576,1).' MB';return round($b/1073741824,2).' GB';}
function fmtD(string $d):string{return date('d.m.Y H:i',strtotime($d));}

// ── Lista transferuri ─────────────────────────────────────────────────────
$pp=20; $pg=max(1,(int)($_GET['page']??1)); $off=($pg-1)*$pp;
$q=trim($_GET['q']??''); $fl=$_GET['f']??'active';
$wf=match($fl){
    'expired'=>"WHERE t.expires_at<NOW() AND t.deleted_at IS NULL",
    'deleted'=>"WHERE t.deleted_at IS NOT NULL",
    'all'    =>"WHERE t.deleted_at IS NULL",
    default  =>"WHERE t.deleted_at IS NULL AND t.expires_at>=NOW()"
};
$wp=''; $wp_params=[];
if($q!==''){$wp="AND (t.bundle_name LIKE ? OR t.token LIKE ? OR t.uploader_ip LIKE ?)";$lk='%'.$q.'%';$wp_params=[$lk,$lk,$lk];}
$cstmt=$db->prepare("SELECT COUNT(*) FROM `{$p}transfers` t $wf $wp");
$cstmt->execute($wp_params);$totRows=(int)$cstmt->fetchColumn();
$totPg=max(1,(int)ceil($totRows/$pp));$pg=min($pg,$totPg);
$lstmt=$db->prepare("SELECT t.*,DATEDIFF(t.expires_at,NOW()) as days_left FROM `{$p}transfers` t $wf $wp ORDER BY t.created_at DESC LIMIT $pp OFFSET $off");
$lstmt->execute($wp_params);$rows=$lstmt->fetchAll();
$admMsg=$_SESSION['adm_msg']??null;unset($_SESSION['adm_msg']);

// Determin tab activ (logs = vizualizare log)
$activeTab = $_GET['tab'] ?? 'transfers';
$logToken  = trim($_GET['lt'] ?? '');
$logData   = [];
if ($activeTab === 'logs' && preg_match('/^[a-f0-9]{64}$/', $logToken)) {
    $lt = $db->prepare("SELECT * FROM `{$p}transfers` WHERE token=? LIMIT 1");
    $lt->execute([$logToken]); $logTransfer = $lt->fetch();
    if ($logTransfer) {
        $ll = $db->prepare("SELECT * FROM `{$p}logs` WHERE transfer_id=? ORDER BY created_at DESC");
        $ll->execute([$logTransfer['id']]); $logData = $ll->fetchAll();
    }
}
?>
<!DOCTYPE html>
<html lang="ro">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin &mdash; <?= htmlspecialchars(APP_NAME) ?></title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#f8fafc;--surface:#fff;--border:#e2e8f0;--text:#0f172a;--t2:#475569;--t3:#94a3b8;--accent:#6366f1;--a2:#8b5cf6;--success:#10b981;--err:#ef4444;--warn:#f59e0b}
body{font-family:'Inter',-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;-webkit-font-smoothing:antialiased}
/* Header */
.hdr{background:var(--surface);border-bottom:1px solid var(--border);padding:0 24px;height:58px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:50;box-shadow:0 1px 3px rgba(0,0,0,.05)}
.hdr-l{display:flex;align-items:center;gap:10px}
.hdr-logo{font-size:16px;font-weight:700;color:var(--text)}
.hdr-badge{background:linear-gradient(135deg,var(--accent),var(--a2));color:#fff;font-size:10px;font-weight:600;padding:2px 8px;border-radius:99px}
.hdr-r{display:flex;align-items:center;gap:8px}
/* Buttons */
.btn{display:inline-flex;align-items:center;gap:6px;padding:7px 14px;border-radius:8px;font-size:13px;font-weight:500;cursor:pointer;border:none;font-family:inherit;transition:all .15s;white-space:nowrap;text-decoration:none}
.btn-primary{background:linear-gradient(135deg,var(--accent),var(--a2));color:#fff;box-shadow:0 2px 8px rgba(99,102,241,.22)}
.btn-primary:hover{opacity:.9}
.btn-outline{background:var(--surface);border:1.5px solid var(--border);color:var(--t2)}
.btn-outline:hover{border-color:var(--accent);color:var(--accent)}
.btn-warn{background:#fffbeb;border:1.5px solid #fde68a;color:#92400e}
.btn-warn:hover{background:#fef3c7}
.btn-danger{background:#fff5f5;border:1.5px solid #fecaca;color:#991b1b}
.btn-danger:hover{background:#fee2e2}
.btn-sm{padding:5px 10px;font-size:12px}
/* Main */
.main{max-width:1300px;margin:0 auto;padding:24px}
/* Stats */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:14px;margin-bottom:24px}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:18px 20px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
.stat-label{font-size:11px;font-weight:600;color:var(--t3);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px}
.stat-val{font-size:24px;font-weight:700;color:var(--text)}
.stat-val.blue{color:var(--accent)}.stat-val.green{color:var(--success)}.stat-val.orange{color:var(--warn)}.stat-val.red{color:var(--err)}
/* Nav tabs */
.nav-tabs{display:flex;gap:2px;background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:4px;margin-bottom:20px;width:fit-content}
.nav-tab{padding:7px 16px;border-radius:8px;font-size:13px;font-weight:500;cursor:pointer;border:none;background:none;color:var(--t2);font-family:inherit;transition:all .15s;text-decoration:none}
.nav-tab.on{background:var(--surface);color:var(--text);box-shadow:0 1px 3px rgba(0,0,0,.08);font-weight:600}
/* Toolbar */
.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px;align-items:center}
.search{flex:1;min-width:180px;position:relative}
.search input{width:100%;border:1.5px solid var(--border);border-radius:10px;padding:9px 14px 9px 36px;font-size:13px;color:var(--text);outline:none;font-family:inherit;background:var(--surface);transition:border-color .2s,box-shadow .2s}
.search input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(99,102,241,.1)}
.search-ico{position:absolute;left:12px;top:50%;transform:translateY(-50%);font-size:14px;pointer-events:none}
.tabs{display:flex;gap:4px}
.tab{padding:7px 13px;border-radius:8px;font-size:12px;font-weight:500;cursor:pointer;border:1.5px solid var(--border);background:var(--surface);color:var(--t2);text-decoration:none;transition:all .15s}
.tab.on{background:var(--accent);border-color:var(--accent);color:#fff}
.tab:hover:not(.on){border-color:var(--accent);color:var(--accent)}
/* Alerts */
.alert{border-radius:10px;padding:11px 15px;font-size:13px;margin-bottom:18px}
.alert-success{background:#f0fdf4;border:1px solid #bbf7d0;color:#166534}
.alert-err{background:#fff5f5;border:1px solid #fecaca;color:#991b1b}
/* Table */
.tbl-wrap{background:var(--surface);border:1px solid var(--border);border-radius:16px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.04)}
table{width:100%;border-collapse:collapse}
th{background:var(--bg);padding:11px 16px;text-align:left;font-size:11px;font-weight:600;color:var(--t3);text-transform:uppercase;letter-spacing:.5px;white-space:nowrap;border-bottom:1px solid var(--border)}
td{padding:11px 16px;border-top:1px solid var(--bg);font-size:13px;vertical-align:middle}
tr:hover td{background:#fafbff}
.fn{font-weight:500;max-width:180px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sub2{font-size:11px;color:var(--t3);margin-top:2px}
.badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:99px;font-size:11px;font-weight:500}
.b-green{background:#f0fdf4;color:#166534}.b-warn{background:#fffbeb;color:#92400e}.b-red{background:#fff5f5;color:#991b1b}.b-gray{background:#f8fafc;color:#64748b}.b-blue{background:#eff6ff;color:#1d4ed8}.b-purple{background:#faf5ff;color:#7c3aed}
.cl{cursor:pointer;color:var(--accent);font-size:11px;text-decoration:underline;background:none;border:none;padding:0;font-family:inherit}
.cl:hover{color:var(--a2)}
.empty{text-align:center;padding:56px 20px;color:var(--t3)}
.empty-ico{font-size:40px;margin-bottom:10px}
/* Pagination */
.pag{display:flex;gap:5px;justify-content:center;margin-top:18px;flex-wrap:wrap}
.pbt{padding:6px 11px;border-radius:8px;font-size:12px;border:1.5px solid var(--border);background:var(--surface);color:var(--t2);text-decoration:none;transition:all .15s}
.pbt.on{background:var(--accent);border-color:var(--accent);color:#fff}
.pbt:hover:not(.on){border-color:var(--accent);color:var(--accent)}
.page-info{text-align:center;margin-top:10px;font-size:12px;color:var(--t3)}
/* Log rows */
.log-up{border-left:3px solid var(--success)}
.log-dl{border-left:3px solid var(--accent)}
/* Password change card */
.pw-card{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:24px;max-width:420px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
.pw-card h3{font-size:15px;font-weight:700;margin-bottom:18px}
.field{margin-bottom:12px}
.field label{display:block;font-size:12px;font-weight:600;color:var(--t2);margin-bottom:4px}
.field input{width:100%;border:1.5px solid var(--border);border-radius:10px;padding:9px 14px;font-size:13px;color:var(--text);outline:none;transition:border-color .2s;font-family:inherit;background:#fafbfc}
.field input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(99,102,241,.1);background:#fff}
/* Log modal */
.modal-bg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.35);z-index:200;align-items:center;justify-content:center;padding:20px}
.modal-bg.show{display:flex}
.modal{background:var(--surface);border-radius:20px;padding:0;max-width:760px;width:100%;max-height:88vh;display:flex;flex-direction:column;box-shadow:0 20px 60px rgba(0,0,0,.2)}
.modal-hdr{padding:20px 24px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
.modal-hdr h3{font-size:15px;font-weight:700}
.modal-close{background:none;border:none;font-size:20px;cursor:pointer;color:var(--t3);padding:0;line-height:1}
.modal-close:hover{color:var(--text)}
.modal-body{overflow-y:auto;padding:20px 24px}
.log-item{display:flex;align-items:flex-start;gap:12px;padding:12px 14px;border-radius:10px;margin-bottom:6px}
.log-item.up{background:rgba(16,185,129,.05);border:1px solid rgba(16,185,129,.15)}
.log-item.dl{background:rgba(99,102,241,.05);border:1px solid rgba(99,102,241,.15)}
.log-ico{font-size:18px;flex-shrink:0;margin-top:1px}
.log-info{flex:1;min-width:0}
.log-row1{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:3px}
.log-type{font-size:12px;font-weight:700}
.log-time{font-size:11px;color:var(--t3)}
.log-row2{font-size:12px;color:var(--t2);display:flex;gap:14px;flex-wrap:wrap}
.log-ip{font-family:monospace;font-size:11px;background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:1px 6px}
</style>
</head>
<body>

<div class="hdr">
  <div class="hdr-l">
    <span class="hdr-logo">🔒 <?= htmlspecialchars(APP_NAME) ?></span>
    <span class="hdr-badge">ADMIN</span>
  </div>
  <div class="hdr-r">
    <span style="font-size:12px;color:var(--t3)">👤 <?= htmlspecialchars($_SESSION['admin_user']) ?></span>
    <form method="POST" style="display:inline">
      <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
      <button type="submit" name="cleanup" class="btn btn-warn" onclick="return confirm('Ștergi toate fișierele expirate?')">🗑 Curăță</button>
    </form>
    <a href="<?= BASE_URL ?>" target="_blank" class="btn btn-outline">🌐 Site</a>
    <form method="POST" style="display:inline">
      <button type="submit" name="logout" class="btn btn-outline">Ieșire</button>
    </form>
  </div>
</div>

<div class="main">
  <?php if($admMsg): ?><div class="alert alert-success"><?= htmlspecialchars($admMsg) ?></div><?php endif; ?>

  <!-- Stats -->
  <div class="stats">
    <div class="stat"><div class="stat-label">Transferuri active</div><div class="stat-val blue"><?= number_format($total) ?></div></div>
    <div class="stat"><div class="stat-label">Fișiere totale</div><div class="stat-val blue"><?= number_format($totalFiles) ?></div></div>
    <div class="stat"><div class="stat-label">Spațiu folosit</div><div class="stat-val green"><?= fmtB($size) ?></div></div>
    <div class="stat"><div class="stat-label">Expirate</div><div class="stat-val orange"><?= number_format($expired) ?></div></div>
    <div class="stat"><div class="stat-label">Descărcări</div><div class="stat-val"><?= number_format($dls) ?></div></div>
  </div>

  <!-- Nav -->
  <div class="nav-tabs">
    <a href="admin.php?tab=transfers" class="nav-tab <?= $activeTab==='transfers'?'on':'' ?>">📋 Transferuri</a>
    <a href="admin.php?tab=password" class="nav-tab <?= $activeTab==='password'?'on':'' ?>">🔑 Schimbă parola</a>
  </div>

  <?php if($activeTab==='password'): ?>
  <!-- ── Schimba parola ── -->
  <div class="pw-card">
    <h3>🔑 Schimbă parola contului</h3>
    <?php if($pwMsg): ?><div class="alert alert-success" style="margin-bottom:14px"><?= htmlspecialchars($pwMsg) ?></div><?php endif; ?>
    <?php if($pwErr): ?><div class="alert alert-err" style="margin-bottom:14px">⚠️ <?= htmlspecialchars($pwErr) ?></div><?php endif; ?>
    <form method="POST">
      <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
      <input type="hidden" name="change_pw" value="1">
      <div class="field">
        <label>Parola curentă</label>
        <input type="password" name="old_password" required placeholder="••••••••" autocomplete="current-password">
      </div>
      <div class="field">
        <label>Parola nouă</label>
        <input type="password" name="new_password" required placeholder="Minim 8 caractere" autocomplete="new-password">
      </div>
      <div class="field" style="margin-bottom:18px">
        <label>Confirmă parola nouă</label>
        <input type="password" name="confirm_password" required placeholder="••••••••" autocomplete="new-password">
      </div>
      <button type="submit" class="btn btn-primary">Salvează parola nouă</button>
    </form>
  </div>

  <?php else: ?>
  <!-- ── Transferuri ── -->
  <div class="toolbar">
    <form method="GET" style="display:contents">
      <input type="hidden" name="f" value="<?= htmlspecialchars($fl) ?>">
      <input type="hidden" name="tab" value="transfers">
      <div class="search">
        <span class="search-ico">🔍</span>
        <input type="text" name="q" placeholder="Caută după nume, token, IP..." value="<?= htmlspecialchars($q) ?>" onchange="this.form.submit()">
      </div>
    </form>
    <div class="tabs">
      <?php foreach(['active'=>'✅ Active','expired'=>'⚠️ Expirate','deleted'=>'🗑 Șterse','all'=>'Toate'] as $k=>$l): ?>
      <a href="admin.php?tab=transfers&f=<?= $k ?><?= $q?'&q='.urlencode($q):'' ?>" class="tab <?= $fl===$k?'on':'' ?>"><?= $l ?></a>
      <?php endforeach; ?>
    </div>
  </div>

  <div class="tbl-wrap">
    <?php if(empty($rows)): ?>
    <div class="empty"><div class="empty-ico">📭</div>Nicio înregistrare.</div>
    <?php else: ?>
    <table>
      <thead><tr>
        <th>Transfer</th><th>Fișiere</th><th>Mărime</th><th>Stare</th>
        <th>Parolă</th><th>Desc.</th><th>Încărcat</th><th>Expiră</th>
        <th>IP Upload</th><th>Activitate</th><th></th>
      </tr></thead>
      <tbody>
      <?php foreach($rows as $t):
        $del=!empty($t['deleted_at']);
        $exp2=!$del&&strtotime($t['expires_at'])<time();
        $dl=(int)$t['days_left'];
        if($del) $sb='<span class="badge b-gray">Șters</span>';
        elseif($exp2) $sb='<span class="badge b-red">Expirat</span>';
        elseif($dl<=3) $sb='<span class="badge b-warn">Expiră '.$dl.'z</span>';
        else $sb='<span class="badge b-green">Activ</span>';
        $dlUrl=BASE_URL.'/download.php?token='.urlencode($t['token']);
        $md=(int)$t['max_downloads']; $dc=(int)$t['download_count'];
        $dlInfo=$md>0?$dc.'/'.$md:(string)$dc;
        // Log count
        $lcStmt=$db->prepare("SELECT COUNT(*) FROM `{$p}logs` WHERE transfer_id=?");
        $lcStmt->execute([$t['id']]); $logCount=(int)$lcStmt->fetchColumn();
      ?>
      <tr>
        <td>
          <div class="fn" title="<?= htmlspecialchars($t['bundle_name']) ?>"><?= htmlspecialchars($t['bundle_name']) ?></div>
          <div class="sub2"><button class="cl" onclick="navigator.clipboard.writeText('<?= htmlspecialchars($dlUrl) ?>').then(()=>{this.textContent='✅ copiat';setTimeout(()=>this.textContent='📋 link',1800)})">📋 link</button></div>
        </td>
        <td style="text-align:center;color:var(--t2)"><?= (int)$t['file_count'] ?></td>
        <td style="white-space:nowrap"><?= fmtB((int)$t['total_size']) ?></td>
        <td><?= $sb ?></td>
        <td><?= $t['password_hash']?'<span class="badge b-blue">🔑 Da</span>':'<span class="badge b-gray">Nu</span>' ?></td>
        <td style="color:var(--t2)"><?= htmlspecialchars($dlInfo) ?></td>
        <td style="color:var(--t2);white-space:nowrap;font-size:12px"><?= fmtD($t['created_at']) ?></td>
        <td style="font-size:12px;white-space:nowrap<?= $exp2?' ;color:var(--err)':'' ?>"><?= $del?'—':fmtD($t['expires_at']) ?></td>
        <td style="color:var(--t3);font-size:11px;font-family:monospace"><?= htmlspecialchars($t['uploader_ip']) ?></td>
        <td>
          <?php if($logCount>0): ?>
          <button class="btn btn-outline btn-sm" onclick="showLogs('<?= htmlspecialchars($t['token']) ?>')">
            📊 <?= $logCount ?> log<?= $logCount>1?'uri':'' ?>
          </button>
          <?php else: ?>
          <span style="color:var(--t3);font-size:12px">—</span>
          <?php endif; ?>
        </td>
        <td>
          <?php if(!$del): ?>
          <form method="POST" onsubmit="return confirm('Ștergi: <?= htmlspecialchars(addslashes($t['bundle_name'])) ?>?')">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
            <input type="hidden" name="del_token" value="<?= htmlspecialchars($t['token']) ?>">
            <button type="submit" class="btn btn-danger btn-sm">🗑</button>
          </form>
          <?php endif; ?>
        </td>
      </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    <?php endif; ?>
  </div>

  <?php if($totPg>1): ?>
  <div class="pag">
    <?php for($i=1;$i<=$totPg;$i++): ?>
    <a href="admin.php?tab=transfers&page=<?=$i?>&f=<?=urlencode($fl)?><?=$q?'&q='.urlencode($q):''?>" class="pbt <?=$i===$pg?'on':''?>"><?=$i?></a>
    <?php endfor; ?>
  </div>
  <?php endif; ?>
  <div class="page-info"><?=$totRows?> înregistrări &nbsp;·&nbsp; Pagina <?=$pg?>/<?=$totPg?></div>
  <?php endif; ?>
</div>

<!-- ── Modal logs ─────────────────────────────────────────────────────── -->
<div class="modal-bg" id="modalBg" onclick="if(event.target===this)closeModal()">
  <div class="modal">
    <div class="modal-hdr">
      <h3 id="modalTitle">Activitate transfer</h3>
      <button class="modal-close" onclick="closeModal()">✕</button>
    </div>
    <div class="modal-body" id="modalBody">
      <div style="text-align:center;padding:40px;color:var(--t3)">Se încarcă...</div>
    </div>
  </div>
</div>

<script>
function showLogs(token){
  document.getElementById('modalBg').classList.add('show');
  document.getElementById('modalBody').innerHTML='<div style="text-align:center;padding:40px;color:var(--t3)">Se încarcă...</div>';
  fetch('admin_logs.php?token='+encodeURIComponent(token)+'&csrf=<?= urlencode($csrf) ?>')
    .then(r=>r.json())
    .then(data=>{
      if(data.error){document.getElementById('modalBody').innerHTML='<div class="alert alert-err">'+data.error+'</div>';return;}
      document.getElementById('modalTitle').textContent='Activitate: '+data.bundle_name+' ('+data.logs.length+' evenimente)';
      if(!data.logs.length){document.getElementById('modalBody').innerHTML='<div style="text-align:center;padding:40px;color:var(--t3)">Nicio activitate înregistrată.</div>';return;}
      let html='';
      data.logs.forEach(l=>{
        const isUp=l.event_type==='upload';
        html+=`<div class="log-item ${isUp?'up':'dl'}">
          <div class="log-ico">${isUp?'⬆️':'⬇️'}</div>
          <div class="log-info">
            <div class="log-row1">
              <span class="log-type" style="color:${isUp?'#059669':'#6366f1'}">${isUp?'UPLOAD':'DOWNLOAD'}</span>
              <span class="log-time">📅 ${l.created_at}</span>
            </div>
            <div class="log-row2">
              <span>💻 ${l.os_name||'—'}</span>
              <span>🌐 ${l.browser_name||'—'}</span>
              <span class="log-ip">${l.ip}</span>
            </div>
          </div>
        </div>`;
      });
      document.getElementById('modalBody').innerHTML=html;
    })
    .catch(()=>{document.getElementById('modalBody').innerHTML='<div class="alert alert-err">Eroare la încărcare.</div>';});
}
function closeModal(){document.getElementById('modalBg').classList.remove('show');}
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeModal();});
</script>
</body>
</html>
