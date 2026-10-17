<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/cloudflare_api.php';

startSecureSession();
requireLogin();

if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !verifyCsrfToken($_POST['csrf_token'] ?? null)) {
    http_response_code(405);
    header('Allow: POST');
    exit('Invalid request');
}

// Get current IP
function getCurrentIP() {
    $services = ['https://api.ipify.org', 'https://ipv4.icanhazip.com', 'https://checkip.amazonaws.com'];
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

$config = loadConfig();
requirePasswordChangeComplete($config);
$results = [];
$currentIP = getCurrentIP();

if (!$currentIP) {
    die("❌ Error: Could not determine current IP address");
}

if (configuredApiToken($config) === '') {
    die("❌ Error: No API token configured");
}

// Check if specific domain should be updated
$specificDomain = isset($_POST['domain']) && is_string($_POST['domain']) ? $_POST['domain'] : null;
if ($specificDomain !== null && !preg_match('/^[a-f0-9]{13,32}$/i', $specificDomain)) {
    http_response_code(400);
    exit('Invalid domain ID');
}

if (isset($config['domains']) && !empty($config['domains'])) {
    foreach ($config['domains'] as $domain) {
        if (!is_array($domain) || !isset($domain['id'], $domain['zone_id'], $domain['record_id'], $domain['name'])) {
            continue;
        }
        // Skip if specific domain requested and this isn't it
        if ($specificDomain && !hash_equals((string) $domain['id'], $specificDomain)) {
            continue;
        }
        
        // Skip disabled domains (unless specifically requested)
        if (empty($domain['enabled']) && !$specificDomain) {
            continue;
        }
        
        $response = updateDNSRecord(
            configuredApiToken($config),
            (string) $domain['zone_id'],
            (string) $domain['record_id'],
            (string) $domain['name'],
            $currentIP,
            !empty($domain['proxied'])
        );
        
        $success = $response['success'] ?? false;
        $error = '';
        
        if (!$success) {
            $error = cloudflareErrors($response);
        }
        
        $results[] = [
            'domain' => (string) $domain['name'],
            'success' => (bool) $success,
            'error' => $error,
            'proxied' => !empty($domain['proxied'])
        ];
        
        // Log the update
        logUpdate((string) $domain['name'], $currentIP, (bool) $success, $error, false);
    }
} else {
    die("❌ Error: No domains configured");
}

if (!$results) {
    http_response_code(404);
    die("❌ Error: Domain not found or no active domains configured");
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNS Update Result</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            padding: 40px;
            max-width: 800px;
            margin: 0 auto;
        }

        .header {
            text-align: center;
            margin-bottom: 30px;
        }

        .header h1 {
            color: #333;
            font-size: 28px;
            margin-bottom: 8px;
        }

        .ip-info {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
            text-align: center;
        }

        .ip-info h3 {
            color: #495057;
            margin-bottom: 10px;
        }

        .ip-info .ip {
            font-size: 24px;
            font-weight: bold;
            color: #667eea;
        }

        .result-card {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
        }

        .result-success {
            border-left: 4px solid #28a745;
            background: #d4edda;
        }

        .result-error {
            border-left: 4px solid #dc3545;
            background: #f8d7da;
        }

        .result-card h4 {
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .result-card p {
            color: #666;
            margin-bottom: 5px;
        }

        .status-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }

        .status-proxied {
            background: #fff3cd;
            color: #856404;
        }

        .btn {
            padding: 12px 24px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            margin-top: 20px;
        }

        .btn:hover {
            transform: translateY(-2px);
        }

        .actions {
            text-align: center;
            margin-top: 30px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔄 DNS Update Result</h1>
        </div>

        <div class="ip-info">
            <h3>Current IP Address</h3>
            <div class="ip"><?= htmlspecialchars($currentIP) ?></div>
        </div>

        <?php foreach ($results as $result): ?>
            <div class="result-card <?= $result['success'] ? 'result-success' : 'result-error' ?>">
                <h4>
                    <?= $result['success'] ? '✅' : '❌' ?>
                    <?= htmlspecialchars($result['domain']) ?>
                    <?php if ($result['proxied']): ?>
                        <span class="status-badge status-proxied">Proxied</span>
                    <?php endif; ?>
                </h4>
                
                <?php if ($result['success']): ?>
                    <p><strong>Update successful!</strong></p>
                    <p>IP address updated to <?= htmlspecialchars($currentIP) ?></p>
                <?php else: ?>
                    <p><strong>Update failed:</strong></p>
                    <p><?= htmlspecialchars($result['error']) ?></p>
                <?php endif; ?>
            </div>
        <?php endforeach; ?>

        <div class="actions">
            <a href="index.php" class="btn">← Back to Dashboard</a>
        </div>
    </div>
</body>
</html>
