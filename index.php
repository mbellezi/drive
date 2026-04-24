<?php
/**
 * index.php — Upload de vídeos + painel admin em um único arquivo.
 *
 * Requisitos:
 * - PHP 8+ com extensão PDO SQLite habilitada.
 * - Este arquivo deve ficar em uma pasta onde o PHP possa criar arquivos/pastas.
 * - Ajuste também o php.ini/webserver para permitir uploads grandes, se necessário.
 *
 * Senha admin: Msjdsn$ndn#
 * Admin: /index.php?admin=1
 */

session_start();

const ADMIN_PASSWORD = 'Msjdsn$ndn#';
const DATA_DIR = __DIR__ . DIRECTORY_SEPARATOR . 'dados';
const TEMP_DIR = DATA_DIR . DIRECTORY_SEPARATOR . '_tmp';
const DB_FILE = __DIR__ . DIRECTORY_SEPARATOR . 'envios.sqlite';
const MAX_BYTES = 3221225472; // 3 GiB
const MAX_BYTES_LABEL = '3 GB';
const CHUNK_BYTES = 8388608; // 8 MiB
const ALLOWED_VIDEO_EXTENSIONS = ['mp4', 'mov', 'avi', 'mkv', 'webm', 'm4v', 'mpeg', 'mpg', '3gp', 'ogv'];

if (!is_dir(DATA_DIR)) {
    mkdir(DATA_DIR, 0755, true);
}
if (!is_dir(TEMP_DIR)) {
    mkdir(TEMP_DIR, 0755, true);
}

// Proteção das pastas de upload: impede listagem e bloqueia acesso/execução de scripts.
// Em hospedagem cPanel/Apache, estes arquivos .htaccess serão criados automaticamente.
$dataHtaccess = DATA_DIR . DIRECTORY_SEPARATOR . '.htaccess';
ensure_security_file($dataHtaccess, <<<'HTACCESS'
Options -Indexes

RemoveHandler .php .php3 .php4 .php5 .php7 .php8 .phtml .phar .cgi .pl .py .sh .asp .aspx .jsp
RemoveType .php .php3 .php4 .php5 .php7 .php8 .phtml .phar .cgi .pl .py .sh .asp .aspx .jsp

<FilesMatch "(^|\.)(php|php[0-9]|phtml|phar|cgi|pl|py|sh|asp|aspx|jsp)(\.|$)">
    Require all denied
</FilesMatch>

<IfModule mod_headers.c>
    Header set X-Content-Type-Options "nosniff"
</IfModule>
HTACCESS);

$tmpHtaccess = TEMP_DIR . DIRECTORY_SEPARATOR . '.htaccess';
ensure_security_file($tmpHtaccess, <<<'HTACCESS'
Options -Indexes
Require all denied
HTACCESS);

$pdo = new PDO('sqlite:' . DB_FILE);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->exec("CREATE TABLE IF NOT EXISTS envios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    email TEXT NOT NULL,
    arquivo_original TEXT NOT NULL,
    arquivo_salvo TEXT NOT NULL,
    tamanho INTEGER NOT NULL,
    mime TEXT,
    criado_em TEXT NOT NULL
)");

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

function json_response(array $data, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

function ensure_security_file(string $path, string $content): void
{
    if (!is_file($path) || file_get_contents($path) !== $content) {
        file_put_contents($path, $content);
    }
}

function sanitize_filename(string $filename): string
{
    $filename = preg_replace('/[^a-zA-Z0-9._-]+/', '_', $filename);
    $filename = trim($filename, '._-');
    return $filename !== '' ? $filename : 'video';
}

function sanitize_stored_basename(string $filename): string
{
    $base = pathinfo($filename, PATHINFO_FILENAME);
    $base = preg_replace('/[^a-zA-Z0-9_-]+/', '_', $base);
    $base = trim($base, '_-');
    return $base !== '' ? $base : 'video';
}

function get_file_extension(string $filename): string
{
    return strtolower(pathinfo($filename, PATHINFO_EXTENSION));
}

function is_allowed_video_extension(string $extension): bool
{
    return in_array($extension, ALLOWED_VIDEO_EXTENSIONS, true);
}

function allowed_video_extensions_label(): string
{
    return implode(', ', ALLOWED_VIDEO_EXTENSIONS);
}

function temp_upload_size(string $tmpUploadDir): int
{
    $size = 0;
    foreach (glob($tmpUploadDir . DIRECTORY_SEPARATOR . '*.part') ?: [] as $part) {
        $size += filesize($part) ?: 0;
    }
    return $size;
}

function require_admin(): void
{
    if (empty($_SESSION['admin_ok'])) {
        header('Location: ?admin=1');
        exit;
    }
}

function bytes_to_human(int $bytes): string
{
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $i = 0;
    $size = (float) $bytes;
    while ($size >= 1024 && $i < count($units) - 1) {
        $size /= 1024;
        $i++;
    }
    return number_format($size, $i === 0 ? 0 : 2, ',', '.') . ' ' . $units[$i];
}

// Endpoint para upload em chunks.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'upload_chunk') {
    $nome = trim((string)($_POST['nome'] ?? ''));
    $email = trim((string)($_POST['email'] ?? ''));
    $uploadId = preg_replace('/[^a-zA-Z0-9_-]/', '', (string)($_POST['upload_id'] ?? ''));
    $chunkIndex = (int)($_POST['chunk_index'] ?? -1);
    $totalChunks = (int)($_POST['total_chunks'] ?? 0);
    $originalName = sanitize_filename((string)($_POST['filename'] ?? 'video'));
    $extension = get_file_extension($originalName);
    $totalSize = (int)($_POST['total_size'] ?? 0);

    if ($nome === '' || mb_strlen($nome) > 160) {
        json_response(['ok' => false, 'message' => 'Informe um nome válido.'], 422);
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        json_response(['ok' => false, 'message' => 'Informe um e-mail válido.'], 422);
    }
    if ($totalSize <= 0 || $totalSize > MAX_BYTES) {
        json_response(['ok' => false, 'message' => 'O vídeo deve ter até ' . MAX_BYTES_LABEL . '.'], 422);
    }
    if (!is_allowed_video_extension($extension)) {
        json_response([
            'ok' => false,
            'message' => 'Formato não permitido. Envie apenas vídeos: ' . allowed_video_extensions_label() . '.'
        ], 422);
    }
    if ($uploadId === '' || $chunkIndex < 0 || $totalChunks < 1 || $chunkIndex >= $totalChunks) {
        json_response(['ok' => false, 'message' => 'Dados do upload inválidos.'], 422);
    }
    if (!isset($_FILES['chunk']) || $_FILES['chunk']['error'] !== UPLOAD_ERR_OK) {
        json_response(['ok' => false, 'message' => 'Falha ao receber parte do arquivo.'], 400);
    }
    if ((int)$_FILES['chunk']['size'] <= 0 || (int)$_FILES['chunk']['size'] > CHUNK_BYTES) {
        json_response(['ok' => false, 'message' => 'Parte do arquivo com tamanho inválido.'], 422);
    }

    $tmpUploadDir = TEMP_DIR . DIRECTORY_SEPARATOR . $uploadId;
    if (!is_dir($tmpUploadDir)) {
        mkdir($tmpUploadDir, 0755, true);
    }

    $chunkPath = $tmpUploadDir . DIRECTORY_SEPARATOR . str_pad((string)$chunkIndex, 8, '0', STR_PAD_LEFT) . '.part';
    if (!move_uploaded_file($_FILES['chunk']['tmp_name'], $chunkPath)) {
        json_response(['ok' => false, 'message' => 'Não foi possível salvar a parte enviada.'], 500);
    }
    $receivedSize = temp_upload_size($tmpUploadDir);
    if ($receivedSize > $totalSize || $receivedSize > MAX_BYTES) {
        @unlink($chunkPath);
        json_response(['ok' => false, 'message' => 'O tamanho recebido ultrapassa o informado.'], 422);
    }

    // Ainda faltam partes.
    if ($chunkIndex < $totalChunks - 1) {
        json_response([
            'ok' => true,
            'complete' => false,
            'received' => $chunkIndex + 1,
            'total' => $totalChunks
        ]);
    }

    // Montagem final quando chega a última parte.
    $safeBase = sanitize_stored_basename($originalName);
    $savedName = '';
    $finalPath = '';

    // Proteção contra colisão: nunca sobrescreve arquivo existente.
    // Mesmo que o nome original seja igual, o prefixo aleatório gera um nome salvo diferente.
    do {
        $savedName = date('Ymd_His') . '_' . bin2hex(random_bytes(16)) . '_' . $safeBase . '.' . $extension;
        $finalPath = DATA_DIR . DIRECTORY_SEPARATOR . $savedName;
    } while (is_file($finalPath));

    $out = fopen($finalPath, 'wb');
    if (!$out) {
        json_response(['ok' => false, 'message' => 'Não foi possível criar o arquivo final.'], 500);
    }

    for ($i = 0; $i < $totalChunks; $i++) {
        $part = $tmpUploadDir . DIRECTORY_SEPARATOR . str_pad((string)$i, 8, '0', STR_PAD_LEFT) . '.part';
        if (!is_file($part)) {
            fclose($out);
            @unlink($finalPath);
            json_response(['ok' => false, 'message' => 'Upload incompleto. Tente novamente.'], 500);
        }
        $in = fopen($part, 'rb');
        stream_copy_to_stream($in, $out);
        fclose($in);
    }
    fclose($out);

    $actualSize = filesize($finalPath);
    if ($actualSize !== $totalSize || $actualSize > MAX_BYTES) {
        @unlink($finalPath);
        json_response(['ok' => false, 'message' => 'O tamanho final do arquivo não confere.'], 500);
    }

    $mime = mime_content_type($finalPath) ?: 'application/octet-stream';
    if (!str_starts_with($mime, 'video/')) {
        @unlink($finalPath);
        json_response(['ok' => false, 'message' => 'Envie somente arquivos de vídeo.'], 422);
    }

    $stmt = $pdo->prepare('INSERT INTO envios (nome, email, arquivo_original, arquivo_salvo, tamanho, mime, criado_em)
                           VALUES (:nome, :email, :arquivo_original, :arquivo_salvo, :tamanho, :mime, :criado_em)');
    $stmt->execute([
        ':nome' => $nome,
        ':email' => $email,
        ':arquivo_original' => $originalName,
        ':arquivo_salvo' => $savedName,
        ':tamanho' => $actualSize,
        ':mime' => $mime,
        ':criado_em' => date('Y-m-d H:i:s'),
    ]);

    foreach (glob($tmpUploadDir . DIRECTORY_SEPARATOR . '*.part') as $part) {
        @unlink($part);
    }
    @rmdir($tmpUploadDir);

    json_response(['ok' => true, 'complete' => true, 'message' => 'Vídeo enviado com sucesso!']);
}

// Login admin.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'admin_login') {
    if (hash_equals(ADMIN_PASSWORD, (string)($_POST['password'] ?? ''))) {
        $_SESSION['admin_ok'] = true;
        header('Location: ?admin=1');
        exit;
    }
    $loginError = 'Senha incorreta.';
}

// Logout admin.
if (isset($_GET['logout'])) {
    unset($_SESSION['admin_ok']);
    header('Location: ?admin=1');
    exit;
}

// Exclusão protegida pelo admin.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'delete_video') {
    require_admin();

    $id = (int)($_POST['id'] ?? 0);
    $stmt = $pdo->prepare('SELECT * FROM envios WHERE id = :id');
    $stmt->execute([':id' => $id]);
    $item = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($item) {
        $path = DATA_DIR . DIRECTORY_SEPARATOR . $item['arquivo_salvo'];
        if (is_file($path)) {
            @unlink($path);
        }

        $delete = $pdo->prepare('DELETE FROM envios WHERE id = :id');
        $delete->execute([':id' => $id]);

        $_SESSION['flash_ok'] = 'Vídeo apagado com sucesso.';
    } else {
        $_SESSION['flash_err'] = 'Envio não encontrado.';
    }

    header('Location: ?admin=1');
    exit;
}

// Download protegido.
if (isset($_GET['download'])) {
    require_admin();
    $id = (int)$_GET['download'];
    $stmt = $pdo->prepare('SELECT * FROM envios WHERE id = :id');
    $stmt->execute([':id' => $id]);
    $item = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$item) {
        http_response_code(404);
        exit('Registro não encontrado.');
    }

    $path = DATA_DIR . DIRECTORY_SEPARATOR . $item['arquivo_salvo'];
    if (!is_file($path)) {
        http_response_code(404);
        exit('Arquivo não encontrado.');
    }

    header('Content-Type: ' . ($item['mime'] ?: 'application/octet-stream'));
    header('Content-Length: ' . filesize($path));
    header('Content-Disposition: attachment; filename="' . str_replace('"', '', $item['arquivo_original']) . '"');
    header('X-Content-Type-Options: nosniff');
    readfile($path);
    exit;
}

$isAdminPage = isset($_GET['admin']);
$envios = [];
if ($isAdminPage && !empty($_SESSION['admin_ok'])) {
    $envios = $pdo->query('SELECT * FROM envios ORDER BY datetime(criado_em) DESC, id DESC')->fetchAll(PDO::FETCH_ASSOC);
}
?>
<!doctype html>
<html lang="pt-BR">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= $isAdminPage ? 'Admin — Envios de Vídeo' : 'Envio de Vídeo' ?></title>
    <style>
        :root {
            --bg1: #0f172a;
            --bg2: #1e1b4b;
            --card: rgba(255, 255, 255, .92);
            --card-strong: #ffffff;
            --text: #111827;
            --muted: #64748b;
            --brand: #7c3aed;
            --brand2: #06b6d4;
            --danger: #dc2626;
            --success: #059669;
            --border: rgba(148, 163, 184, .35);
            --shadow: 0 24px 80px rgba(2, 6, 23, .28);
            --radius: 28px;
        }

        * { box-sizing: border-box; }

        body {
            margin: 0;
            min-height: 100vh;
            font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            color: var(--text);
            background:
                radial-gradient(circle at top left, rgba(6, 182, 212, .32), transparent 36rem),
                radial-gradient(circle at bottom right, rgba(124, 58, 237, .34), transparent 34rem),
                linear-gradient(135deg, var(--bg1), var(--bg2));
            padding: 28px;
        }

        a { color: inherit; }

        .shell {
            width: min(1120px, 100%);
            margin: 0 auto;
        }

        .topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
            margin-bottom: 26px;
            color: white;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 12px;
            font-weight: 800;
            letter-spacing: -.03em;
            font-size: clamp(1.15rem, 2vw, 1.5rem);
        }

        .logo {
            width: 44px;
            height: 44px;
            display: grid;
            place-items: center;
            border-radius: 16px;
            background: linear-gradient(135deg, var(--brand), var(--brand2));
            box-shadow: 0 14px 34px rgba(6, 182, 212, .26);
        }

        .navlink {
            text-decoration: none;
            color: rgba(255,255,255,.9);
            border: 1px solid rgba(255,255,255,.18);
            padding: 10px 14px;
            border-radius: 999px;
            backdrop-filter: blur(16px);
            background: rgba(255,255,255,.08);
            font-weight: 700;
            transition: .2s ease;
        }

        .navlink:hover { transform: translateY(-1px); background: rgba(255,255,255,.14); }

        .hero {
            display: grid;
            grid-template-columns: 1fr 1.05fr;
            gap: 28px;
            align-items: center;
        }

        .copy {
            color: white;
            padding: 20px 8px;
        }

        .eyebrow {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(255,255,255,.12);
            border: 1px solid rgba(255,255,255,.18);
            padding: 8px 12px;
            border-radius: 999px;
            font-weight: 800;
            font-size: .84rem;
            margin-bottom: 18px;
        }

        h1 {
            margin: 0;
            font-size: clamp(2.1rem, 5vw, 4.6rem);
            line-height: .95;
            letter-spacing: -.075em;
        }

        .copy p {
            font-size: clamp(1rem, 2vw, 1.18rem);
            color: rgba(255,255,255,.78);
            line-height: 1.7;
            max-width: 54ch;
        }

        .card {
            background: var(--card);
            border: 1px solid rgba(255,255,255,.5);
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            backdrop-filter: blur(22px);
            overflow: hidden;
        }

        .card-inner { padding: clamp(22px, 4vw, 36px); }

        .card h2 {
            margin: 0 0 8px;
            font-size: clamp(1.45rem, 2.5vw, 2rem);
            letter-spacing: -.04em;
        }

        .subtitle {
            margin: 0 0 26px;
            color: var(--muted);
            line-height: 1.55;
        }

        .field { margin-bottom: 18px; }

        label {
            display: block;
            margin-bottom: 8px;
            font-size: .9rem;
            font-weight: 800;
            color: #334155;
        }

        input[type="text"], input[type="email"], input[type="password"], input[type="file"] {
            width: 100%;
            border: 1px solid var(--border);
            background: rgba(255,255,255,.88);
            border-radius: 18px;
            padding: 15px 16px;
            font: inherit;
            outline: none;
            transition: .18s ease;
        }

        input:focus {
            border-color: rgba(124, 58, 237, .75);
            box-shadow: 0 0 0 4px rgba(124, 58, 237, .12);
        }

        .dropzone {
            border: 2px dashed rgba(124, 58, 237, .35);
            background: linear-gradient(135deg, rgba(124,58,237,.08), rgba(6,182,212,.08));
            border-radius: 24px;
            padding: 22px;
        }

        .hint {
            color: var(--muted);
            font-size: .9rem;
            margin-top: 8px;
        }

        button, .button {
            border: 0;
            cursor: pointer;
            width: 100%;
            border-radius: 18px;
            padding: 15px 18px;
            color: white;
            font-weight: 900;
            font-size: 1rem;
            background: linear-gradient(135deg, var(--brand), var(--brand2));
            box-shadow: 0 16px 36px rgba(124, 58, 237, .28);
            transition: .2s ease;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }

        button:hover, .button:hover { transform: translateY(-1px); filter: saturate(1.08); }
        button:disabled { opacity: .6; cursor: not-allowed; transform: none; }

        .progress-wrap {
            display: none;
            margin-top: 18px;
            background: #e2e8f0;
            height: 14px;
            border-radius: 999px;
            overflow: hidden;
        }

        .progress-bar {
            height: 100%;
            width: 0%;
            background: linear-gradient(90deg, var(--brand), var(--brand2));
            transition: width .15s ease;
        }

        .status {
            margin-top: 14px;
            font-weight: 800;
            min-height: 24px;
        }

        .status.ok { color: var(--success); }
        .status.err { color: var(--danger); }

        .admin-card { margin-top: 22px; }

        .table-wrap { overflow-x: auto; }
        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 760px;
        }

        th, td {
            text-align: left;
            padding: 15px 14px;
            border-bottom: 1px solid #e2e8f0;
            vertical-align: middle;
        }

        th {
            color: #475569;
            font-size: .82rem;
            text-transform: uppercase;
            letter-spacing: .08em;
        }

        td { color: #1f2937; }
        .muted { color: var(--muted); }
        .pill {
            display: inline-flex;
            align-items: center;
            border-radius: 999px;
            padding: 6px 10px;
            background: #f1f5f9;
            color: #475569;
            font-weight: 800;
            font-size: .85rem;
            white-space: nowrap;
        }

        .download {
            width: auto;
            padding: 10px 13px;
            border-radius: 14px;
            font-size: .9rem;
        }

        .actions {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }

        .actions form { margin: 0; }

        .delete {
            width: auto;
            padding: 10px 13px;
            border-radius: 14px;
            font-size: .9rem;
            background: linear-gradient(135deg, #ef4444, #b91c1c);
            box-shadow: 0 12px 26px rgba(220, 38, 38, .22);
        }

        .empty {
            padding: 44px;
            text-align: center;
            color: var(--muted);
        }

        .footer-note {
            color: rgba(255,255,255,.62);
            text-align: center;
            margin-top: 22px;
            font-size: .9rem;
        }

        @media (max-width: 860px) {
            body { padding: 18px; }
            .hero { grid-template-columns: 1fr; }
            .copy { padding: 8px 0 0; }
            .topbar { align-items: flex-start; }
        }
    </style>
</head>
<body>
<div class="shell">
    <header class="topbar">
        <div class="brand">
            <div class="logo">▶</div>
            <span><?= $isAdminPage ? 'Painel de envios' : 'Upload de vídeo' ?></span>
        </div>
        <?php if ($isAdminPage): ?>
            <a class="navlink" href="<?= !empty($_SESSION['admin_ok']) ? '?admin=1&logout=1' : './' ?>"><?= !empty($_SESSION['admin_ok']) ? 'Sair' : 'Voltar ao envio' ?></a>
        <?php else: ?>
        <?php endif; ?>
    </header>

    <?php if (!$isAdminPage): ?>
        <main class="hero">
            <section class="copy">
                <div class="eyebrow">Upload seguro • até <?= MAX_BYTES_LABEL ?></div>
                <h1>Envie seu vídeo com facilidade.</h1>
                <p>Preencha seus dados, selecione o arquivo e acompanhe o envio em tempo real. O vídeo será registrado.</p>
            </section>

            <section class="card">
                <div class="card-inner">
                    <h2>Formulário de envio</h2>
                    <p class="subtitle">Preencha o formulário com seus dados e escolha o seu arquivo com o vídeo.</p>

                    <form id="uploadForm">
                        <div class="field">
                            <label for="nome">Nome completo</label>
                            <input id="nome" name="nome" type="text" maxlength="160" required placeholder="Ex.: Ana Silva">
                        </div>
                        <div class="field">
                            <label for="email">E-mail</label>
                            <input id="email" name="email" type="email" required placeholder="ana@email.com">
                        </div>
                        <div class="field dropzone">
                            <label for="video">Arquivo de vídeo</label>
                            <input id="video" name="video" type="file" accept="video/mp4,video/quicktime,video/x-msvideo,video/x-matroska,video/webm,video/x-m4v,video/mpeg,video/3gpp,video/ogg,.mp4,.mov,.avi,.mkv,.webm,.m4v,.mpeg,.mpg,.3gp,.ogv" required>
                            <div class="hint">Tamanho máximo: <?= MAX_BYTES_LABEL ?>. Formatos de vídeo aceitos pelo navegador.</div>
                        </div>
                        <button id="submitBtn" type="submit">Enviar vídeo</button>
                        <div class="progress-wrap" id="progressWrap"><div class="progress-bar" id="progressBar"></div></div>
                        <div class="status" id="status"></div>
                    </form>
                </div>
            </section>
        </main>
    <?php else: ?>
        <?php if (empty($_SESSION['admin_ok'])): ?>
            <section class="hero">
                <section class="copy">
                    <div class="eyebrow">Acesso restrito</div>
                    <h1>Área administrativa.</h1>
                    <p>Entre com a senha para listar envios do mais recente ao mais antigo e baixar os arquivos recebidos.</p>
                </section>

                <section class="card">
                    <div class="card-inner">
                        <h2>Login do admin</h2>
                        <p class="subtitle">Informe a senha administrativa.</p>
                        <form method="post">
                            <input type="hidden" name="action" value="admin_login">
                            <div class="field">
                                <label for="password">Senha</label>
                                <input id="password" name="password" type="password" required autofocus>
                            </div>
                            <button type="submit">Entrar</button>
                            <?php if (!empty($loginError)): ?>
                                <div class="status err"><?= h($loginError) ?></div>
                            <?php endif; ?>
                        </form>
                    </div>
                </section>
            </section>
        <?php else: ?>
            <section class="card admin-card">
                <div class="card-inner">
                    <h2>Envios recebidos</h2>
                    <p class="subtitle">Listagem em ordem de data, da mais recente para a mais antiga.</p>

                    <?php if (!empty($_SESSION['flash_ok'])): ?>
                        <div class="status ok"><?= h($_SESSION['flash_ok']); unset($_SESSION['flash_ok']); ?></div>
                    <?php endif; ?>
                    <?php if (!empty($_SESSION['flash_err'])): ?>
                        <div class="status err"><?= h($_SESSION['flash_err']); unset($_SESSION['flash_err']); ?></div>
                    <?php endif; ?>

                    <?php if (!$envios): ?>
                        <div class="empty">Nenhum envio foi recebido ainda.</div>
                    <?php else: ?>
                        <div class="table-wrap">
                            <table>
                                <thead>
                                <tr>
                                    <th>Data</th>
                                    <th>Nome</th>
                                    <th>E-mail</th>
                                    <th>Arquivo</th>
                                    <th>Tamanho</th>
                                    <th>Ações</th>
                                </tr>
                                </thead>
                                <tbody>
                                <?php foreach ($envios as $envio): ?>
                                    <tr>
                                        <td><span class="pill"><?= h(date('d/m/Y H:i', strtotime($envio['criado_em']))) ?></span></td>
                                        <td><?= h($envio['nome']) ?></td>
                                        <td><span class="muted"><?= h($envio['email']) ?></span></td>
                                        <td><?= h($envio['arquivo_original']) ?></td>
                                        <td><?= h(bytes_to_human((int)$envio['tamanho'])) ?></td>
                                        <td>
                                            <div class="actions">
                                                <a class="button download" href="?admin=1&download=<?= (int)$envio['id'] ?>">Baixar</a>
                                                <form method="post" onsubmit="return confirm('Tem certeza que deseja apagar este vídeo? Esta ação não pode ser desfeita.');">
                                                    <input type="hidden" name="action" value="delete_video">
                                                    <input type="hidden" name="id" value="<?= (int)$envio['id'] ?>">
                                                    <button class="button delete" type="submit">Apagar</button>
                                                </form>
                                            </div>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php endif; ?>
                </div>
            </section>
        <?php endif; ?>
    <?php endif; ?>

</div>

<?php if (!$isAdminPage): ?>
<script>
(() => {
    const MAX_BYTES = <?= MAX_BYTES ?>;
    const CHUNK_SIZE = <?= CHUNK_BYTES ?>; // 8 MiB por parte
    const form = document.getElementById('uploadForm');
    const btn = document.getElementById('submitBtn');
    const status = document.getElementById('status');
    const progressWrap = document.getElementById('progressWrap');
    const progressBar = document.getElementById('progressBar');

    function setStatus(message, type = '') {
        status.textContent = message;
        status.className = 'status ' + type;
    }

    function setProgress(percent) {
        progressWrap.style.display = 'block';
        progressBar.style.width = Math.max(0, Math.min(100, percent)) + '%';
    }

    form.addEventListener('submit', async (event) => {
        event.preventDefault();

        const nome = document.getElementById('nome').value.trim();
        const email = document.getElementById('email').value.trim();
        const fileInput = document.getElementById('video');
        const file = fileInput.files[0];

        if (!nome || !email || !file) {
            setStatus('Preencha todos os campos.', 'err');
            return;
        }
        const allowedExtensions = <?= json_encode(ALLOWED_VIDEO_EXTENSIONS) ?>;
        const extension = file.name.includes('.') ? file.name.split('.').pop().toLowerCase() : '';
        if (!allowedExtensions.includes(extension)) {
            setStatus('Formato não permitido. Envie apenas vídeos: ' + allowedExtensions.join(', ') + '.', 'err');
            return;
        }
        if (!file.type.startsWith('video/')) {
            setStatus('Escolha um arquivo de vídeo.', 'err');
            return;
        }
        if (file.size > MAX_BYTES) {
            setStatus('O arquivo ultrapassa o limite de <?= MAX_BYTES_LABEL ?>.', 'err');
            return;
        }

        btn.disabled = true;
        setStatus('Iniciando envio...', '');
        setProgress(0);

        const uploadId = (crypto.randomUUID ? crypto.randomUUID() : String(Date.now()) + Math.random().toString(16).slice(2)).replace(/[^a-zA-Z0-9_-]/g, '');
        const totalChunks = Math.ceil(file.size / CHUNK_SIZE);

        try {
            for (let i = 0; i < totalChunks; i++) {
                const start = i * CHUNK_SIZE;
                const end = Math.min(file.size, start + CHUNK_SIZE);
                const chunk = file.slice(start, end);

                const data = new FormData();
                data.append('action', 'upload_chunk');
                data.append('nome', nome);
                data.append('email', email);
                data.append('upload_id', uploadId);
                data.append('chunk_index', String(i));
                data.append('total_chunks', String(totalChunks));
                data.append('filename', file.name);
                data.append('total_size', String(file.size));
                data.append('chunk', chunk, file.name + '.part');

                const response = await fetch(location.href, {
                    method: 'POST',
                    body: data
                });

                let result;
                try {
                    result = await response.json();
                } catch (_) {
                    throw new Error('Resposta inválida do servidor. Verifique limites de upload no PHP/webserver.');
                }

                if (!response.ok || !result.ok) {
                    throw new Error(result.message || 'Falha no upload.');
                }

                const percent = ((i + 1) / totalChunks) * 100;
                setProgress(percent);
                setStatus(`Enviando... ${Math.round(percent)}%`, '');

                if (result.complete) {
                    setProgress(100);
                    setStatus(result.message || 'Vídeo enviado com sucesso!', 'ok');
                    form.reset();
                }
            }
        } catch (error) {
            setStatus(error.message || 'Erro inesperado durante o envio.', 'err');
        } finally {
            btn.disabled = false;
        }
    });
})();
</script>
<?php endif; ?>
</body>
</html>
