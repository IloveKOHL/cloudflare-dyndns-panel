<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    die("This script can only be executed from command line.\n");
}

require_once __DIR__ . '/bootstrap.php';

echo "=== Cloudflare DynDNS Cron Test ===\n\n";
$failed = false;

echo 'PHP version: ' . PHP_VERSION . "\n";
if (version_compare(PHP_VERSION, '7.4.0', '<')) {
    echo "ERROR: PHP 7.4 or newer is required.\n";
    $failed = true;
}

foreach (['json', 'openssl'] as $extension) {
    $loaded = extension_loaded($extension);
    echo ($loaded ? 'OK' : 'ERROR') . ": {$extension} extension\n";
    $failed = $failed || !$loaded;
}

try {
    $config = loadConfig();
    echo "OK: configuration loaded from protected data directory\n";
    echo (configuredApiToken($config) !== '' ? 'OK' : 'ERROR') . ": Cloudflare API token configured\n";
    echo 'INFO: ' . count($config['domains']) . " domain(s) configured\n";
    echo 'INFO: update interval is ' . $config['update_interval'] . "\n";
    if (configuredApiToken($config) === '') {
        $failed = true;
    }
} catch (Throwable $exception) {
    echo 'ERROR: ' . $exception->getMessage() . "\n";
    $failed = true;
}

foreach ([dataDirectory(), dataPath(CONFIG_FILE), __DIR__ . '/auto_update.php'] as $path) {
    $readable = is_readable($path);
    echo ($readable ? 'OK' : 'ERROR') . ": readable {$path}\n";
    $failed = $failed || !$readable;
}

if (!is_writable(dataDirectory())) {
    echo "ERROR: protected data directory is not writable\n";
    $failed = true;
} else {
    echo "OK: protected data directory is writable\n";
}

$context = stream_context_create(['http' => ['timeout' => 10, 'max_redirects' => 0]]);
$ip = @file_get_contents('https://api.ipify.org', false, $context, 0, 64);
$ip = $ip === false ? '' : trim($ip);
if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
    echo "ERROR: public IPv4 detection failed\n";
    $failed = true;
} else {
    echo "OK: public IPv4 detection works\n";
}

echo "\nSuggested cron command:\n";
echo '* * * * * ' . escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/auto_update.php') . "\n";
echo "The script enforces the configured interval internally.\n";

exit($failed ? 1 : 0);
