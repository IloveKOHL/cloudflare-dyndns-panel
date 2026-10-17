<?php
declare(strict_types=1);

const CONFIG_FILE = 'config.json';
const LOG_FILE = 'update_log.json';

function dataDirectory(): string
{
    static $directory = null;

    if ($directory !== null) {
        return $directory;
    }

    $configured = getenv('DYNDNS_DATA_DIR');
    $directory = $configured !== false && trim($configured) !== ''
        ? rtrim(trim($configured), "/\\")
        : (DIRECTORY_SEPARATOR === '/'
            ? '/var/lib/cloudflare-dyndns-panel'
            : __DIR__ . DIRECTORY_SEPARATOR . 'data');

    $absolute = DIRECTORY_SEPARATOR === '\\'
        ? preg_match('/^(?:[a-zA-Z]:[\\\\\/]|\\\\\\\\)/', $directory) === 1
        : isset($directory[0]) && $directory[0] === '/';
    if (!$absolute) {
        throw new RuntimeException('DYNDNS_DATA_DIR must be an absolute path.');
    }

    if (!is_dir($directory)) {
        if (!mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new RuntimeException('Unable to create the application data directory.');
        }
        @chmod($directory, 0700);
    }
    // is_writable() is unreliable on Windows ACLs; writes below remain fail-closed.
    if (DIRECTORY_SEPARATOR !== '\\' && !is_writable($directory)) {
        throw new RuntimeException('The application data directory is not writable.');
    }

    // Defense in depth for manual Apache installations that keep data below the web root.
    $denyFile = $directory . DIRECTORY_SEPARATOR . '.htaccess';
    if (!file_exists($denyFile)) {
        @file_put_contents($denyFile, "Require all denied\n", LOCK_EX);
        @chmod($denyFile, 0600);
    }

    return $directory;
}

function dataPath(string $filename): string
{
    if ($filename === '' || basename($filename) !== $filename || strpbrk($filename, "/\\") !== false) {
        throw new InvalidArgumentException('Invalid data filename.');
    }

    return dataDirectory() . DIRECTORY_SEPARATOR . $filename;
}

function atomicWrite(string $path, string $contents, int $mode = 0600): bool
{
    $temporary = $path . '.tmp.' . bin2hex(random_bytes(8));
    $bytes = @file_put_contents($temporary, $contents, LOCK_EX);
    if ($bytes === false) {
        return false;
    }

    @chmod($temporary, $mode);

    if (@rename($temporary, $path)) {
        @chmod($path, $mode);
        return true;
    }

    // Windows cannot atomically replace an existing file. Production Linux systems use
    // the atomic rename above; this fallback keeps local Windows development functional.
    if (DIRECTORY_SEPARATOR === '\\' && file_exists($path) && @unlink($path) && @rename($temporary, $path)) {
        @chmod($path, $mode);
        return true;
    }

    @unlink($temporary);
    return false;
}

function migrateLegacyData(): void
{
    static $migrated = false;
    if ($migrated) {
        return;
    }
    $migrated = true;

    foreach ([CONFIG_FILE, LOG_FILE, 'last_ip.txt', 'last_run.txt'] as $filename) {
        $legacy = __DIR__ . DIRECTORY_SEPARATOR . $filename;
        if (!is_file($legacy)) {
            continue;
        }

        $destination = dataPath($filename);
        if (file_exists($destination)) {
            $destination = dataPath('legacy-' . gmdate('Ymd-His') . '-' . $filename);
        }

        if (!@rename($legacy, $destination)) {
            if (!@copy($legacy, $destination) || !@unlink($legacy)) {
                throw new RuntimeException('Unable to move legacy data out of the public web directory.');
            }
        }
        @chmod($destination, 0600);
    }
}

function readJsonData(string $filename, $default)
{
    migrateLegacyData();
    $path = dataPath($filename);
    if (!is_file($path)) {
        return $default;
    }

    $contents = @file_get_contents($path);
    if ($contents === false) {
        throw new RuntimeException('Unable to read application data.');
    }

    try {
        return json_decode($contents, true, 64, JSON_THROW_ON_ERROR);
    } catch (JsonException $exception) {
        throw new RuntimeException('Application data is corrupt; refusing to overwrite it.', 0, $exception);
    }
}

function writeJsonData(string $filename, $value): bool
{
    try {
        $json = json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    } catch (JsonException $exception) {
        return false;
    }

    return atomicWrite(dataPath($filename), $json . "\n");
}

function generateInitialPassword(): string
{
    $configured = getenv('DYNDNS_INITIAL_PASSWORD');
    if ($configured !== false && $configured !== '') {
        if (strlen($configured) < 12) {
            throw new RuntimeException('DYNDNS_INITIAL_PASSWORD must contain at least 12 characters.');
        }
        return $configured;
    }

    $password = rtrim(strtr(base64_encode(random_bytes(24)), '+/', '-_'), '=');
    if (!atomicWrite(dataPath('initial_password.txt'), $password . "\n")) {
        throw new RuntimeException('Unable to store the generated initial password.');
    }
    return $password;
}

function defaultConfig(): array
{
    return [
        'password' => password_hash(generateInitialPassword(), PASSWORD_DEFAULT),
        'must_change_password' => true,
        'api_token' => '',
        'domains' => [],
        'update_interval' => 'manual',
    ];
}

function loadConfig(): array
{
    $config = readJsonData(CONFIG_FILE, null);
    if ($config === null) {
        $config = defaultConfig();
        if (!saveConfig($config)) {
            throw new RuntimeException('Unable to create the application configuration.');
        }
    }

    if (!is_array($config) || !isset($config['password']) || !is_string($config['password'])) {
        throw new RuntimeException('The application configuration is invalid; refusing to reset credentials.');
    }

    $changed = false;
    $defaults = [
        'must_change_password' => false,
        'api_token' => '',
        'domains' => [],
        'update_interval' => 'manual',
    ];
    foreach ($defaults as $key => $value) {
        if (!array_key_exists($key, $config)) {
            $config[$key] = $value;
            $changed = true;
        }
    }

    // Invalidate the historical public default during an upgrade.
    if (password_verify('changeme', $config['password'])) {
        $config['password'] = password_hash(generateInitialPassword(), PASSWORD_DEFAULT);
        $config['must_change_password'] = true;
        $changed = true;
    }

    if (!is_array($config['domains'])) {
        throw new RuntimeException('The configured domain list is invalid.');
    }

    $environmentToken = getenv('CLOUDFLARE_API_TOKEN');
    if ($environmentToken !== false && trim($environmentToken) !== '' && $config['api_token'] !== '') {
        $config['api_token'] = '';
        $changed = true;
    }

    if ($changed && !saveConfig($config)) {
        throw new RuntimeException('Unable to migrate the application configuration.');
    }

    return $config;
}

function saveConfig(array $config): bool
{
    $environmentToken = getenv('CLOUDFLARE_API_TOKEN');
    if ($environmentToken !== false && trim($environmentToken) !== '') {
        // Do not retain a second plaintext copy when a deployment secret is configured.
        $config['api_token'] = '';
    }

    return writeJsonData(CONFIG_FILE, $config);
}

function configuredApiToken(array $config): string
{
    $environmentToken = getenv('CLOUDFLARE_API_TOKEN');
    if ($environmentToken !== false && trim($environmentToken) !== '') {
        return trim($environmentToken);
    }

    return isset($config['api_token']) && is_string($config['api_token'])
        ? trim($config['api_token'])
        : '';
}

function loadLogs(): array
{
    $logs = readJsonData(LOG_FILE, []);
    return is_array($logs) ? $logs : [];
}

function logUpdate(string $domain, string $ip, bool $success, string $error = '', bool $automatic = false): bool
{
    $lock = @fopen(dataPath('update_log.lock'), 'c+');
    if ($lock === false || !flock($lock, LOCK_EX)) {
        if (is_resource($lock)) {
            fclose($lock);
        }
        return false;
    }

    try {
        $logs = loadLogs();
        array_unshift($logs, [
            'timestamp' => date('Y-m-d H:i:s'),
            'domain' => $domain,
            'ip' => $ip,
            'success' => $success,
            'error' => $error,
            'automatic' => $automatic,
        ]);
        return writeJsonData(LOG_FILE, array_slice($logs, 0, 100));
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

function clearLogs(): bool
{
    $path = dataPath(LOG_FILE);
    return !file_exists($path) || @unlink($path);
}

function isHttpsRequest(): bool
{
    $forced = getenv('DYNDNS_FORCE_HTTPS');
    return ($forced !== false && in_array(strtolower($forced), ['1', 'true', 'yes'], true))
        || (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== '' && $_SERVER['HTTPS'] !== 'off');
}

function cspNonce(): string
{
    static $nonce = null;
    if ($nonce === null) {
        $nonce = base64_encode(random_bytes(18));
    }
    return $nonce;
}

function startSecureSession(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_samesite', 'Strict');
    ini_set('session.cookie_secure', isHttpsRequest() ? '1' : '0');
    session_name('dyndns_panel');
    session_start();

    header('Cache-Control: no-store');
    header('Pragma: no-cache');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
    header("Content-Security-Policy: default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'; img-src 'self' data:; connect-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'nonce-" . cspNonce() . "'");
}

function isLoggedIn(): bool
{
    return isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;
}

function requireLogin(bool $json = false): void
{
    if (isLoggedIn()) {
        return;
    }

    http_response_code(403);
    if ($json) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['success' => false, 'error' => 'Not logged in']);
    } else {
        echo 'Not logged in!';
    }
    exit;
}

function requirePasswordChangeComplete(array $config, bool $json = false): void
{
    if (empty($config['must_change_password'])) {
        return;
    }

    if ($json) {
        http_response_code(403);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['success' => false, 'error' => 'Change the initial password first']);
        exit;
    }

    header('Location: change_password.php');
    exit;
}

function csrfToken(): string
{
    if (!isset($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verifyCsrfToken($candidate): bool
{
    return is_string($candidate)
        && isset($_SESSION['csrf_token'])
        && is_string($_SESSION['csrf_token'])
        && hash_equals($_SESSION['csrf_token'], $candidate);
}

function logoutSession(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
    }
    session_destroy();
}

function loginThrottlePath(): string
{
    $address = isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : 'unknown';
    return dataPath('login-' . hash('sha256', $address) . '.json');
}

function recentLoginFailures(): array
{
    $path = loginThrottlePath();
    if (!is_file($path)) {
        return [];
    }
    $contents = @file_get_contents($path);
    $failures = $contents === false ? [] : json_decode($contents, true);
    if (!is_array($failures)) {
        return [];
    }
    $cutoff = time() - 900;
    return array_values(array_filter($failures, static function ($timestamp) use ($cutoff): bool {
        return is_int($timestamp) && $timestamp >= $cutoff;
    }));
}

function loginRetryAfter(): int
{
    $failures = recentLoginFailures();
    if (count($failures) < 5) {
        return 0;
    }
    return max(1, 900 - (time() - min($failures)));
}

function recordLoginFailure(): void
{
    $failures = recentLoginFailures();
    $failures[] = time();
    atomicWrite(loginThrottlePath(), json_encode($failures) . "\n");
}

function clearLoginFailures(): void
{
    $path = loginThrottlePath();
    if (is_file($path)) {
        @unlink($path);
    }
}

function validateCloudflareId(string $id): bool
{
    return preg_match('/^[a-f0-9]{32}$/i', $id) === 1;
}

function validateDomainName(string $name): bool
{
    $candidate = strpos($name, '*.') === 0 ? substr($name, 2) : $name;
    return $candidate !== ''
        && strlen($candidate) <= 253
        && filter_var($candidate, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false;
}

function validatedDomainInput(array $input): array
{
    $zoneId = isset($input['zone_id']) ? trim((string) $input['zone_id']) : '';
    $recordId = isset($input['record_id']) ? trim((string) $input['record_id']) : '';
    $nameKey = array_key_exists('domain_name', $input) ? 'domain_name' : 'name';
    $name = isset($input[$nameKey]) ? strtolower(rtrim(trim((string) $input[$nameKey]), '.')) : '';

    if (!validateCloudflareId($zoneId) || !validateCloudflareId($recordId) || !validateDomainName($name)) {
        throw new InvalidArgumentException('Invalid Cloudflare zone, record, or domain name.');
    }

    return [
        'zone_id' => $zoneId,
        'record_id' => $recordId,
        'name' => $name,
        'proxied' => isset($input['proxied']) && in_array((string) $input['proxied'], ['1', 'on'], true),
    ];
}

function allowedUpdateIntervals(): array
{
    return ['manual', '5min', '15min', '30min', '1hour', '6hours', '12hours', 'daily'];
}
