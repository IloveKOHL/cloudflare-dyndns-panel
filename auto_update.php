<?php
declare(strict_types=1);

// Automatic DNS Update Script for Cron Jobs
if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    die("Error: This script can only be executed from command line or cron.\n");
}

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/cloudflare_api.php';

$processLock = @fopen(dataPath('auto_update.lock'), 'c+');
if ($processLock === false || !flock($processLock, LOCK_EX | LOCK_NB)) {
    fwrite(STDERR, "Another automatic update is already running.\n");
    exit(0);
}

function getCurrentIP()
{
    $services = [
        'https://api.ipify.org',
        'https://ipv4.icanhazip.com',
        'https://checkip.amazonaws.com',
        'https://ipinfo.io/ip',
    ];
    $context = stream_context_create(['http' => ['timeout' => 10, 'max_redirects' => 0]]);
    $detected = [];

    foreach ($services as $service) {
        $ip = @file_get_contents($service, false, $context, 0, 64);
        $ip = $ip === false ? '' : trim($ip);
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            $detected[] = $ip;
        }
    }

    if (!$detected) {
        return false;
    }

    $counts = array_count_values($detected);
    arsort($counts);
    $ip = (string) array_key_first($counts);
    return $counts[$ip] >= 2 ? $ip : false;
}

function hasIPChanged(string $currentIP): bool
{
    $path = dataPath('last_ip.txt');
    if (!is_file($path)) {
        return true;
    }
    $lastIP = @file_get_contents($path);
    return $lastIP === false || trim($lastIP) !== $currentIP;
}

function shouldRunUpdate(string $interval): bool
{
    $seconds = [
        '5min' => 300,
        '15min' => 900,
        '30min' => 1800,
        '1hour' => 3600,
        '6hours' => 21600,
        '12hours' => 43200,
        'daily' => 86400,
    ];
    if (!isset($seconds[$interval])) {
        return false;
    }

    $path = dataPath('last_run.txt');
    $now = time();
    $lastRun = is_file($path) ? (int) @file_get_contents($path) : 0;
    if (($now - $lastRun) < $seconds[$interval]) {
        return false;
    }

    return atomicWrite($path, (string) $now . "\n");
}

function cliDomainName(array $domain): string
{
    $name = isset($domain['name']) && is_string($domain['name']) ? $domain['name'] : 'unknown';
    return str_replace(["\r", "\n"], '', $name);
}

echo '[' . date('Y-m-d H:i:s') . "] Starting automatic DNS update check...\n";

try {
    $config = loadConfig();
} catch (Throwable $exception) {
    fwrite(STDERR, '[' . date('Y-m-d H:i:s') . '] ERROR: ' . $exception->getMessage() . "\n");
    exit(1);
}

$interval = isset($config['update_interval']) ? (string) $config['update_interval'] : 'manual';
if ($interval === 'manual') {
    echo '[' . date('Y-m-d H:i:s') . "] INFO: Automatic updates disabled (manual mode)\n";
    exit(0);
}
if (!in_array($interval, allowedUpdateIntervals(), true)) {
    fwrite(STDERR, '[' . date('Y-m-d H:i:s') . "] ERROR: Invalid update interval\n");
    exit(1);
}

$apiToken = configuredApiToken($config);
if ($apiToken === '') {
    fwrite(STDERR, '[' . date('Y-m-d H:i:s') . "] ERROR: No API token configured\n");
    exit(1);
}
if (empty($config['domains'])) {
    echo '[' . date('Y-m-d H:i:s') . "] WARNING: No domains configured\n";
    exit(0);
}
if (!shouldRunUpdate($interval)) {
    echo '[' . date('Y-m-d H:i:s') . "] INFO: Update interval not reached, skipping\n";
    exit(0);
}

echo '[' . date('Y-m-d H:i:s') . "] Getting current IP address from multiple services...\n";
$currentIP = getCurrentIP();
if ($currentIP === false) {
    fwrite(STDERR, '[' . date('Y-m-d H:i:s') . "] ERROR: IP services did not agree on a valid IPv4 address\n");
    exit(1);
}

echo '[' . date('Y-m-d H:i:s') . "] Current IP: {$currentIP}\n";
if (!hasIPChanged($currentIP)) {
    echo '[' . date('Y-m-d H:i:s') . "] INFO: IP address unchanged, skipping update\n";
    exit(0);
}

$updateCount = 0;
$errorCount = 0;
$skippedCount = 0;

foreach ($config['domains'] as $domain) {
    if (!is_array($domain)) {
        $errorCount++;
        continue;
    }
    $displayName = cliDomainName($domain);
    if (empty($domain['enabled'])) {
        echo '[' . date('Y-m-d H:i:s') . "] INFO: Skipping disabled domain: {$displayName}\n";
        $skippedCount++;
        continue;
    }

    $zoneId = isset($domain['zone_id']) ? (string) $domain['zone_id'] : '';
    $recordId = isset($domain['record_id']) ? (string) $domain['record_id'] : '';
    $name = isset($domain['name']) ? (string) $domain['name'] : '';
    if (!validateCloudflareId($zoneId) || !validateCloudflareId($recordId) || !validateDomainName($name)) {
        echo '[' . date('Y-m-d H:i:s') . "] ERROR: Invalid domain configuration for: {$displayName}\n";
        $errorCount++;
        continue;
    }

    echo '[' . date('Y-m-d H:i:s') . "] Updating {$displayName}...\n";
    $response = updateDNSRecord($apiToken, $zoneId, $recordId, $name, $currentIP, !empty($domain['proxied']));
    $success = !empty($response['success']);
    $error = $success ? '' : cloudflareErrors($response);

    if ($success) {
        echo '[' . date('Y-m-d H:i:s') . "] SUCCESS: {$displayName} updated to {$currentIP}\n";
        $updateCount++;
    } else {
        echo '[' . date('Y-m-d H:i:s') . "] ERROR: Failed to update {$displayName}: {$error}\n";
        $errorCount++;
    }
    logUpdate($name, $currentIP, $success, $error, true);
}

if ($errorCount === 0 && $updateCount > 0 && !atomicWrite(dataPath('last_ip.txt'), $currentIP . "\n")) {
    fwrite(STDERR, '[' . date('Y-m-d H:i:s') . "] ERROR: DNS updated but last IP state could not be saved\n");
    exit(1);
}

echo '[' . date('Y-m-d H:i:s') . "] Summary: {$updateCount} successful, {$errorCount} failed, {$skippedCount} skipped\n";
exit($errorCount > 0 ? 1 : 0);
