<?php
/**
 * GoogleDrive.php — Helper Google Drive API v3 pentru PHP 8.x
 *
 * Zero dependente externe. Foloseste doar:
 *  - openssl_sign()   (disponibil pe orice shared hosting cu PHP)
 *  - cURL
 *
 * Cum se configureaza:
 *  1. Google Cloud Console → Creeaza proiect → Activeaza Google Drive API
 *  2. IAM & Admin → Service Accounts → Creeaza → Descarca JSON cu cheia
 *  3. Copiaza fisierul JSON INAFARA public_html (ex: /home/i0sub/private/gdrive-sa.json)
 *  4. Creeaza un folder in Google Drive → Share catre email-ul service account (Editor)
 *  5. Copiaza ID-ul folderului din URL (ce vine dupa /folders/)
 *  6. Seteaza GDRIVE_SA_KEY_FILE si GDRIVE_FOLDER_ID in config.php
 */

class GoogleDrive
{
    private string $accessToken = '';
    private int    $tokenExpiry = 0;
    private array  $saKey       = [];

    private const OAUTH_ENDPOINT = 'https://oauth2.googleapis.com/token';
    private const DRIVE_UPLOAD   = 'https://www.googleapis.com/upload/drive/v3/files';
    private const DRIVE_FILES    = 'https://www.googleapis.com/drive/v3/files';
    private const SCOPE          = 'https://www.googleapis.com/auth/drive';

    public function __construct(string $keyFilePath)
    {
        if (!file_exists($keyFilePath)) {
            throw new RuntimeException("Service account key file not found: {$keyFilePath}");
        }
        $json = file_get_contents($keyFilePath);
        if ($json === false) {
            throw new RuntimeException("Cannot read service account key file.");
        }
        $this->saKey = json_decode($json, true);
        if (empty($this->saKey['private_key']) || empty($this->saKey['client_email'])) {
            throw new RuntimeException("Invalid service account key file format.");
        }
    }

    // ── OAuth2 JWT Bearer Token ───────────────────────────────────────────

    private function getAccessToken(): string
    {
        if ($this->accessToken && time() < $this->tokenExpiry - 30) {
            return $this->accessToken;
        }

        $now    = time();
        $header = base64_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT']));
        $claim  = base64_encode(json_encode([
            'iss'   => $this->saKey['client_email'],
            'scope' => self::SCOPE,
            'aud'   => self::OAUTH_ENDPOINT,
            'exp'   => $now + 3600,
            'iat'   => $now,
        ]));

        // URL-safe base64 (RFC 7515)
        $header = rtrim(strtr($header, '+/', '-_'), '=');
        $claim  = rtrim(strtr($claim,  '+/', '-_'), '=');

        $sig = '';
        $ok  = openssl_sign(
            "{$header}.{$claim}",
            $sig,
            $this->saKey['private_key'],
            'SHA256'
        );
        if (!$ok) {
            throw new RuntimeException("JWT signing failed.");
        }
        $sig = rtrim(strtr(base64_encode($sig), '+/', '-_'), '=');
        $jwt = "{$header}.{$claim}.{$sig}";

        $response = $this->curlPost(self::OAUTH_ENDPOINT, http_build_query([
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion'  => $jwt,
        ]), ['Content-Type: application/x-www-form-urlencoded']);

        $data = json_decode($response, true);
        if (empty($data['access_token'])) {
            throw new RuntimeException("Failed to obtain access token: " . $response);
        }

        $this->accessToken = $data['access_token'];
        $this->tokenExpiry = $now + (int)($data['expires_in'] ?? 3600);
        return $this->accessToken;
    }

    // ── Upload fisier ─────────────────────────────────────────────────────

    /**
     * Uploadeaza un fisier pe Google Drive.
     *
     * @param  string $tmpPath       Calea fisierului temporar (din $_FILES)
     * @param  string $originalName  Numele original al fisierului
     * @param  string $mimeType      MIME type detectat
     * @param  string $folderId      ID-ul folderului Drive in care se salveaza
     * @return string                Drive file ID
     */
    public function uploadFile(
        string $tmpPath,
        string $originalName,
        string $mimeType,
        string $folderId
    ): string {
        $token = $this->getAccessToken();

        // Fisierele mici (<= 5MB): multipart upload simplu
        // Fisierele mari: resumable upload
        $fileSize = filesize($tmpPath);

        if ($fileSize <= 5 * 1024 * 1024) {
            return $this->uploadMultipart($tmpPath, $originalName, $mimeType, $folderId, $token);
        } else {
            return $this->uploadResumable($tmpPath, $originalName, $mimeType, $folderId, $token, $fileSize);
        }
    }

    private function uploadMultipart(
        string $tmpPath,
        string $originalName,
        string $mimeType,
        string $folderId,
        string $token
    ): string {
        $metadata = json_encode([
            'name'    => $originalName,
            'parents' => [$folderId],
        ]);

        $fileContent = file_get_contents($tmpPath);
        if ($fileContent === false) {
            throw new RuntimeException("Cannot read temp file for upload.");
        }

        $boundary = bin2hex(random_bytes(16));
        $body  = "--{$boundary}\r\n";
        $body .= "Content-Type: application/json; charset=UTF-8\r\n\r\n";
        $body .= $metadata . "\r\n";
        $body .= "--{$boundary}\r\n";
        $body .= "Content-Type: {$mimeType}\r\n\r\n";
        $body .= $fileContent . "\r\n";
        $body .= "--{$boundary}--";

        $response = $this->curlPost(
            self::DRIVE_UPLOAD . '?uploadType=multipart&fields=id&supportsAllDrives=true',
            $body,
            [
                "Authorization: Bearer {$token}",
                "Content-Type: multipart/related; boundary={$boundary}",
            ]
        );

        $data = json_decode($response, true);
        if (empty($data['id'])) {
            throw new RuntimeException("Drive upload failed: " . $response);
        }
        return $data['id'];
    }

    private function uploadResumable(
        string $tmpPath,
        string $originalName,
        string $mimeType,
        string $folderId,
        string $token,
        int    $fileSize
    ): string {
        // Pas 1: Initializeaza sesiunea resumable
        $metadata = json_encode([
            'name'    => $originalName,
            'parents' => [$folderId],
        ]);

        $ch = curl_init(self::DRIVE_UPLOAD . '?uploadType=resumable&fields=id&supportsAllDrives=true');
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $metadata,
            CURLOPT_HEADER         => true,
            CURLOPT_HTTPHEADER     => [
                "Authorization: Bearer {$token}",
                "Content-Type: application/json; charset=UTF-8",
                "X-Upload-Content-Type: {$mimeType}",
                "X-Upload-Content-Length: {$fileSize}",
            ],
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_TIMEOUT        => 30,
        ]);
        $resp = curl_exec($ch);
        $info = curl_getinfo($ch);
        curl_close($ch);

        // Extrage Location header
        if (!preg_match('/^Location:\s*(.+)$/im', (string)$resp, $m)) {
            throw new RuntimeException("Resumable upload init failed. Response: " . $resp);
        }
        $uploadUrl = trim($m[1]);

        // Pas 2: Incarca fisierul in chunks de 8MB
        $chunkSize = 8 * 1024 * 1024;
        $handle    = fopen($tmpPath, 'rb');
        if (!$handle) {
            throw new RuntimeException("Cannot open file for resumable upload.");
        }

        $uploaded = 0;
        $driveId  = '';

        while ($uploaded < $fileSize) {
            $chunk     = fread($handle, $chunkSize);
            $chunkLen  = strlen($chunk);
            $rangeEnd  = $uploaded + $chunkLen - 1;
            $rangeHeader = "Content-Range: bytes {$uploaded}-{$rangeEnd}/{$fileSize}";

            $ch = curl_init($uploadUrl);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CUSTOMREQUEST  => 'PUT',
                CURLOPT_POSTFIELDS     => $chunk,
                CURLOPT_HTTPHEADER     => [
                    "Authorization: Bearer {$token}",
                    "Content-Type: {$mimeType}",
                    "Content-Length: {$chunkLen}",
                    $rangeHeader,
                ],
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_TIMEOUT        => 300,
            ]);
            $result = curl_exec($ch);
            $code   = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            $uploaded += $chunkLen;

            // 200/201 = upload complet
            if ($code === 200 || $code === 201) {
                $data    = json_decode($result, true);
                $driveId = $data['id'] ?? '';
                break;
            }
            // 308 = mai are chunk-uri de incarcat
            if ($code !== 308) {
                fclose($handle);
                throw new RuntimeException("Resumable upload chunk failed (HTTP {$code}): " . $result);
            }
        }
        fclose($handle);

        if (empty($driveId)) {
            throw new RuntimeException("Resumable upload completed but no file ID returned.");
        }
        return $driveId;
    }

    // ── Download / Stream ─────────────────────────────────────────────────

    /**
     * Stream-eaza un fisier din Drive direct catre browser.
     * Trebuie apelat inainte de a trimite orice alt output.
     */
    public function streamFile(string $driveFileId): void
    {
        $token = $this->getAccessToken();
        $url   = self::DRIVE_FILES . '/' . urlencode($driveFileId) . '?alt=media';

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => false,    // scrie direct in output
            CURLOPT_WRITEFUNCTION  => function($ch, $data) {
                echo $data;
                return strlen($data);
            },
            CURLOPT_HTTPHEADER     => [
                "Authorization: Bearer {$token}",
            ],
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT        => 0,        // fara timeout pentru fisiere mari
            CURLOPT_BUFFERSIZE     => 65536,
        ]);
        $ok   = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if (!$ok || $code !== 200) {
            throw new RuntimeException("Drive stream failed (HTTP {$code}).");
        }
    }

    /**
     * Returneaza metadata unui fisier (name, mimeType, size).
     */
    public function getFileMetadata(string $driveFileId): array
    {
        $token    = $this->getAccessToken();
        $url      = self::DRIVE_FILES . '/' . urlencode($driveFileId)
                  . '?fields=id,name,mimeType,size';
        $response = $this->curlGet($url, ["Authorization: Bearer {$token}"]);
        $data     = json_decode($response, true);
        if (empty($data['id'])) {
            throw new RuntimeException("Cannot get file metadata: " . $response);
        }
        return $data;
    }

    // ── Stergere fisier ───────────────────────────────────────────────────

    /**
     * Sterge definitiv un fisier din Drive.
     * Returneaza true daca a reusit sau daca fisierul nu mai exista (404).
     */
    public function deleteFile(string $driveFileId): bool
    {
        $token = $this->getAccessToken();
        $url   = self::DRIVE_FILES . '/' . urlencode($driveFileId);

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST  => 'DELETE',
            CURLOPT_HTTPHEADER     => [
                "Authorization: Bearer {$token}",
            ],
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_TIMEOUT        => 30,
        ]);
        curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        return $code === 204 || $code === 404;
    }

    // ── Helpers cURL ─────────────────────────────────────────────────────

    private function curlPost(string $url, mixed $body, array $headers = []): string
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $body,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_TIMEOUT        => 60,
        ]);
        $result = curl_exec($ch);
        $errno  = curl_errno($ch);
        $error  = curl_error($ch);
        curl_close($ch);

        if ($errno) {
            throw new RuntimeException("cURL error ({$errno}): {$error}");
        }
        return (string)$result;
    }

    private function curlGet(string $url, array $headers = []): string
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_TIMEOUT        => 30,
        ]);
        $result = curl_exec($ch);
        $errno  = curl_errno($ch);
        $error  = curl_error($ch);
        curl_close($ch);

        if ($errno) {
            throw new RuntimeException("cURL error ({$errno}): {$error}");
        }
        return (string)$result;
    }
}
