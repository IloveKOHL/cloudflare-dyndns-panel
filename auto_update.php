<?php
// Automatic DNS Update Script for Cron Jobs
// This script runs independently without web sessions

// Prevent direct web access - only allow command line execution
if (isset($_SERVER['HTTP_HOST'])) {
    http_response_code(403);
    die("Error: This script can only be executed from command line or cron job.\n");
}

// Change to script directory to ensure relative paths work
chdir(dirname(__FILE__));

// Load configuration directly from file
function loadConfig() {
    if (!file_exists('config.json')) {
        return null;
    }
    
    $config = json_decode(file_get_contents('config.json'), true);
    
    // Validate config structure
    if (!$config || !is_array($config)) {
        return null;
    }
    
    // Check required fields
    if (!isset($config['api_token']) || !isset($config['domains'])) {
        return null;
    }
    if (!is_array($config['domains'])) {
        $config['domains'] = [];
    } elseif (!empty($config['domains'])) {
        foreach ($config['domains'] as &$domain) {
            if (!isset($domain['type'])) {
                $domain['type'] = 'A';
            } else {
                $domain['type'] = strtoupper($domain['type']) === 'AAAA' ? 'AAAA' : 'A';
            }
        }
        unset($domain);
    }
    
    return $config;
}

// Get current IP for a DNS record type
function getCurrentIP($type = 'A') {
    $type = strtoupper($type) === 'AAAA' ? 'AAAA' : 'A';
    $services = $type === 'AAAA'
        ? ['https://api6.ipify.org', 'https://ipv6.icanhazip.com', 'https://v6.ident.me']
        : ['https://api.ipify.org', 'https://ipv4.icanhazip.com', 'https://checkip.amazonaws.com'];
    $flag = $type === 'AAAA' ? FILTER_FLAG_IPV6 : FILTER_FLAG_IPV4;
    
    foreach ($services as $service) {
        $ip = @file_get_contents($service);
        if ($ip && filter_var(trim($ip), FILTER_VALIDATE_IP, $flag)) {
            return trim($ip);
        }
    }
    
    return false;
}

// Update DNS record via Cloudflare API
function updateDNSRecord($apiToken, $zoneId, $recordId, $name, $ip, $recordType = 'A', $proxied = false) {
    $url = "https://api.cloudflare.com/client/v4/zones/$zoneId/dns_records/$recordId";
    $data = [
        "type" => $recordType,
        "name" => $name,
        "content" => $ip,
        "ttl" => 120,
        "proxied" => $proxied
    ];

    $options = [
        "http" => [
            "header" => [
                "Authorization: Bearer $apiToken",
                "Content-Type: application/json",
                "User-Agent: CloudflareDynDNS/1.0"
            ],
            "method" => "PUT",
            "content" => json_encode($data),
            "timeout" => 30
        ]
    ];
    
    $context = stream_context_create($options);
    $result = @file_get_contents($url, false, $context);
    
    if ($result === false) {
        return ['success' => false, 'errors' => [['message' => 'Network error or timeout']]];
    }
    
    $response = json_decode($result, true);
    if (!$response) {
        return ['success' => false, 'errors' => [['message' => 'Invalid API response']]];
    }
    
    return $response;
}

// Log update with timestamp
function logUpdate($domain, $ip, $recordType, $success, $error = '', $auto = true) {
    $logEntry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'domain' => $domain,
        'ip' => $ip,
        'record_type' => $recordType,
        'success' => $success,
        'error' => $error,
        'automatic' => $auto
    ];
    
    $logFile = 'update_log.json';
    $logs = [];
    
    if (file_exists($logFile)) {
        $content = file_get_contents($logFile);
        if ($content) {
            $logs = json_decode($content, true) ?: [];
        }
    }
    
    array_unshift($logs, $logEntry);
    
    // Keep only last 100 entries
    $logs = array_slice($logs, 0, 100);
    
    file_put_contents($logFile, json_encode($logs, JSON_PRETTY_PRINT));
}

// Check if IP has changed since last update
function hasIPChanged($recordType, $currentIP) {
    $recordType = strtoupper($recordType) === 'AAAA' ? 'AAAA' : 'A';
    $storeFile = 'last_ip.json';
    $legacyFile = 'last_ip.txt';
    $data = [];
    
    if (file_exists($storeFile)) {
        $content = file_get_contents($storeFile);
        $decoded = json_decode($content, true);
        if (is_array($decoded)) {
            $data = $decoded;
        }
    } elseif (file_exists($legacyFile)) {
        $legacyIp = trim(file_get_contents($legacyFile));
        if ($legacyIp !== '') {
            $data['A'] = $legacyIp;
        }
        @unlink($legacyFile);
    }
    
    $previous = $data[$recordType] ?? null;
    
    if ($previous !== $currentIP) {
        $data[$recordType] = $currentIP;
        file_put_contents($storeFile, json_encode($data, JSON_PRETTY_PRINT));
        return true;
    }
    
    return false;
}

// Validate update interval timing
function shouldRunUpdate($interval) {
    $lastRunFile = 'last_run.txt';
    $now = time();
    
    if (!file_exists($lastRunFile)) {
        file_put_contents($lastRunFile, $now);
        return true;
    }
    
    $lastRun = intval(file_get_contents($lastRunFile));
    $timeDiff = $now - $lastRun;
    
    // Define minimum intervals in seconds
    $intervals = [
        '5min' => 300,      // 5 minutes
        '15min' => 900,     // 15 minutes
        '30min' => 1800,    // 30 minutes
        '1hour' => 3600,    // 1 hour
        '6hours' => 21600,  // 6 hours
        '12hours' => 43200, // 12 hours
        'daily' => 86400    // 24 hours
    ];
    
    $minInterval = $intervals[$interval] ?? 0;
    
    if ($timeDiff >= $minInterval) {
        file_put_contents($lastRunFile, $now);
        return true;
    }
    
    return false;
}

// Main execution starts here
echo "[" . date('Y-m-d H:i:s') . "] Starting automatic DNS update check...\n";

// Load configuration
$config = loadConfig();

if (!$config) {
    echo "[" . date('Y-m-d H:i:s') . "] ERROR: No valid configuration file found\n";
    echo "Make sure config.json exists and contains valid configuration.\n";
    exit(1);
}

// Check if automatic updates are enabled
if (!isset($config['update_interval']) || $config['update_interval'] === 'manual') {
    echo "[" . date('Y-m-d H:i:s') . "] INFO: Automatic updates disabled (manual mode)\n";
    exit(0);
}

// Check if we should run based on interval
if (!shouldRunUpdate($config['update_interval'])) {
    echo "[" . date('Y-m-d H:i:s') . "] INFO: Update interval not reached, skipping\n";
    exit(0);
}

// Validate API token
if (empty($config['api_token'])) {
    echo "[" . date('Y-m-d H:i:s') . "] ERROR: No API token configured\n";
    echo "Please configure your Cloudflare API token in the web panel.\n";
    exit(1);
}

// Check if domains are configured
if (!isset($config['domains']) || empty($config['domains'])) {
    echo "[" . date('Y-m-d H:i:s') . "] WARNING: No domains configured\n";
    exit(0);
}

$updateCount = 0;
$errorCount = 0;
$skippedCount = 0;
$domainsToProcess = [];

// Validate and collect enabled domains
foreach ($config['domains'] as $domain) {
    if (!isset($domain['enabled']) || !$domain['enabled']) {
        echo "[" . date('Y-m-d H:i:s') . "] INFO: Skipping disabled domain: {$domain['name']}\n";
        $skippedCount++;
        continue;
    }
    
    if (!isset($domain['zone_id']) || !isset($domain['record_id']) || !isset($domain['name'])) {
        echo "[" . date('Y-m-d H:i:s') . "] ERROR: Invalid domain configuration for: " . ($domain['name'] ?? 'unknown') . "\n";
        $errorCount++;
        continue;
    }
    
    $domain['type'] = isset($domain['type']) && strtoupper($domain['type']) === 'AAAA' ? 'AAAA' : 'A';
    $domainsToProcess[] = $domain;
}

if (empty($domainsToProcess)) {
    echo "[" . date('Y-m-d H:i:s') . "] WARNING: No enabled domains to update\n";
    exit($errorCount > 0 ? 1 : 0);
}

// Determine required record types
$requiredTypes = [];
foreach ($domainsToProcess as $domain) {
    $requiredTypes[$domain['type']] = true;
}

$currentIPs = [];
$typeChanges = [];

foreach (array_keys($requiredTypes) as $recordType) {
    $label = $recordType === 'AAAA' ? 'IPv6' : 'IPv4';
    echo "[" . date('Y-m-d H:i:s') . "] Getting current $label address...\n";
    $ip = getCurrentIP($recordType);
    if (!$ip) {
        echo "[" . date('Y-m-d H:i:s') . "] ERROR: Could not determine current $label address\n";
        exit(1);
    }
    echo "[" . date('Y-m-d H:i:s') . "] Current $label: $ip\n";
    $currentIPs[$recordType] = $ip;
    $typeChanges[$recordType] = hasIPChanged($recordType, $ip);
    if ($typeChanges[$recordType]) {
        echo "[" . date('Y-m-d H:i:s') . "] INFO: $label changed since last update\n";
    } else {
        echo "[" . date('Y-m-d H:i:s') . "] INFO: $label unchanged since last update\n";
    }
}

if (!in_array(true, $typeChanges, true)) {
    echo "[" . date('Y-m-d H:i:s') . "] INFO: IP addresses unchanged, skipping update\n";
    exit(0);
}

echo "[" . date('Y-m-d H:i:s') . "] IP change detected, updating DNS records...\n";

// Process each domain
foreach ($domainsToProcess as $domain) {
    $recordType = $domain['type'];
    if (empty($typeChanges[$recordType])) {
        echo "[" . date('Y-m-d H:i:s') . "] INFO: Skipping {$domain['name']} (no $recordType change)\n";
        $skippedCount++;
        continue;
    }
    
    echo "[" . date('Y-m-d H:i:s') . "] Updating {$domain['name']} ($recordType)...\n";
    
    $response = updateDNSRecord(
        $config['api_token'],
        $domain['zone_id'],
        $domain['record_id'],
        $domain['name'],
        $currentIPs[$recordType],
        $recordType,
        $domain['proxied'] ?? false
    );
    
    $success = $response['success'] ?? false;
    $error = '';
    
    if ($success) {
        echo "[" . date('Y-m-d H:i:s') . "] SUCCESS: {$domain['name']} updated to {$currentIPs[$recordType]}\n";
        $updateCount++;
    } else {
        if (isset($response['errors']) && is_array($response['errors'])) {
            $error = implode(', ', array_column($response['errors'], 'message'));
        } else {
            $error = 'Unknown API error';
        }
        echo "[" . date('Y-m-d H:i:s') . "] ERROR: Failed to update {$domain['name']}: $error\n";
        $errorCount++;
    }
    
    logUpdate($domain['name'], $currentIPs[$recordType], $recordType, $success, $error, true);
    
    if (count($domainsToProcess) > 1) {
        usleep(500000);
    }
}

// Summary
echo "[" . date('Y-m-d H:i:s') . "] Update completed\n";
echo "[" . date('Y-m-d H:i:s') . "] Summary: $updateCount successful, $errorCount failed, $skippedCount skipped\n";

if ($errorCount > 0) {
    echo "[" . date('Y-m-d H:i:s') . "] WARNING: Some updates failed, check logs for details\n";
    exit(1);
}

echo "[" . date('Y-m-d H:i:s') . "] All updates completed successfully\n";
exit(0);
?>
