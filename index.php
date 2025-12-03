<?php
session_start();

// Load configuration
function loadConfig() {
    if (!file_exists('config.json')) {
        // Create new config with default password
        $defaultConfig = [
            'password' => password_hash('changeme', PASSWORD_DEFAULT),
            'api_token' => '',
            'domains' => [],
            'update_interval' => 'manual'
        ];
        
        // Save the default config
        file_put_contents('config.json', json_encode($defaultConfig, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        
        return $defaultConfig;
    }
    
    $config = json_decode(file_get_contents('config.json'), true);
    
    // Check if config is empty or corrupted
    if (!$config || !is_array($config)) {
        // Create new config with default password
        $defaultConfig = [
            'password' => password_hash('changeme', PASSWORD_DEFAULT),
            'api_token' => '',
            'domains' => [],
            'update_interval' => 'manual'
        ];
        
        // Save the default config
        file_put_contents('config.json', json_encode($defaultConfig, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        
        return $defaultConfig;
    }
    
    // Ensure all required keys exist
    if (!isset($config['password'])) {
        $config['password'] = password_hash('changeme', PASSWORD_DEFAULT);
    }
    if (!isset($config['api_token'])) {
        $config['api_token'] = '';
    }
    if (!isset($config['domains']) || !is_array($config['domains'])) {
        $config['domains'] = [];
    }
    if (!empty($config['domains'])) {
        foreach ($config['domains'] as &$domain) {
            if (!isset($domain['type'])) {
                $domain['type'] = 'A';
            } else {
                $domain['type'] = strtoupper($domain['type']) === 'AAAA' ? 'AAAA' : 'A';
            }
        }
        unset($domain);
    }
    if (!isset($config['update_interval'])) {
        $config['update_interval'] = 'manual';
    }
    
    return $config;
}

// Save configuration
function saveConfig($config) {
    return file_put_contents('config.json', json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
}

// Get current IP for given record type
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

// Generate cron command based on interval
function generateCronCommand($interval, $scriptPath) {
    $phpPath = '/usr/bin/php'; // Adjust if needed
    $fullPath = realpath($scriptPath);
    
    switch ($interval) {
        case '5min':
            return "*/5 * * * * $phpPath $fullPath";
        case '15min':
            return "*/15 * * * * $phpPath $fullPath";
        case '30min':
            return "*/30 * * * * $phpPath $fullPath";
        case '1hour':
            return "0 * * * * $phpPath $fullPath";
        case '6hours':
            return "0 */6 * * * $phpPath $fullPath";
        case '12hours':
            return "0 */12 * * * $phpPath $fullPath";
        case 'daily':
            return "0 0 * * * $phpPath $fullPath";
        default:
            return null;
    }
}

// Get interval options
function getIntervalOptions() {
    return [
        'manual' => 'Manual only (no automatic updates)',
        '5min' => 'Every 5 minutes',
        '15min' => 'Every 15 minutes',
        '30min' => 'Every 30 minutes',
        '1hour' => 'Every hour',
        '6hours' => 'Every 6 hours',
        '12hours' => 'Every 12 hours',
        'daily' => 'Daily (once per day)'
    ];
}

// Get Cloudflare zones
function getCloudflareZones($apiToken) {
    $url = "https://api.cloudflare.com/client/v4/zones";
    $options = [
        "http" => [
            "header" => [
                "Authorization: Bearer $apiToken",
                "Content-Type: application/json"
            ],
            "method" => "GET"
        ]
    ];
    $context = stream_context_create($options);
    $result = @file_get_contents($url, false, $context);
    
    if ($result) {
        $response = json_decode($result, true);
        return $response['success'] ? $response['result'] : [];
    }
    return [];
}

// Get DNS records for a zone
function getDNSRecords($apiToken, $zoneId) {
    $records = [];
    $types = ['A', 'AAAA'];
    
    foreach ($types as $type) {
        $url = "https://api.cloudflare.com/client/v4/zones/$zoneId/dns_records?type=$type";
        $options = [
            "http" => [
                "header" => [
                    "Authorization: Bearer $apiToken",
                    "Content-Type: application/json"
                ],
                "method" => "GET"
            ]
        ];
        $context = stream_context_create($options);
        $result = @file_get_contents($url, false, $context);
        
        if ($result) {
            $response = json_decode($result, true);
            if ($response['success']) {
                $records = array_merge($records, $response['result']);
            }
        }
    }
    
    if (!empty($records)) {
        usort($records, function($a, $b) {
            if ($a['name'] === $b['name']) {
                return strcmp($a['type'], $b['type']);
            }
            return strcmp($a['name'], $b['name']);
        });
    }
    
    return $records;
}

$config = loadConfig();
$error = '';
$success = '';

// Handle login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    if (password_verify($_POST['password'], $config['password'])) {
        $_SESSION['logged_in'] = true;
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        header("Location: index.php");
        exit;
    } else {
        $error = "Invalid password";
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: index.php");
    exit;
}

// Handle API token save
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_token']) && isset($_SESSION['logged_in'])) {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $error = "Invalid request";
    } else {
        $config['api_token'] = trim($_POST['api_token']);
        if (saveConfig($config)) {
            $success = "API Token saved successfully!";
        } else {
            $error = "Error saving API Token";
        }
    }
}

// Handle update interval save
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_interval']) && isset($_SESSION['logged_in'])) {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $error = "Invalid request";
    } else {
        $config['update_interval'] = $_POST['update_interval'];
        if (saveConfig($config)) {
            $success = "Update interval saved successfully!";
        } else {
            $error = "Error saving update interval";
        }
    }
}

// Handle domain addition
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_domain']) && isset($_SESSION['logged_in'])) {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $error = "Invalid request";
    } else {
        $recordType = strtoupper($_POST['record_type'] ?? 'A');
        $recordType = $recordType === 'AAAA' ? 'AAAA' : 'A';
        $domain = [
            'id' => uniqid(),
            'zone_id' => trim($_POST['zone_id']),
            'record_id' => trim($_POST['record_id']),
            'name' => trim($_POST['domain_name']),
            'type' => $recordType,
            'proxied' => isset($_POST['proxied']),
            'enabled' => true
        ];
        
        if (!isset($config['domains'])) {
            $config['domains'] = [];
        }
        
        $config['domains'][] = $domain;
        
        if (saveConfig($config)) {
            $success = "Domain added successfully!";
        } else {
            $error = "Error adding domain";
        }
    }
}

// Handle domain deletion
if (isset($_GET['delete_domain']) && isset($_SESSION['logged_in'])) {
    $domainId = $_GET['delete_domain'];
    if (isset($config['domains'])) {
        $config['domains'] = array_filter($config['domains'], function($domain) use ($domainId) {
            return $domain['id'] !== $domainId;
        });
        $config['domains'] = array_values($config['domains']);
        
        if (saveConfig($config)) {
            $success = "Domain deleted successfully!";
        } else {
            $error = "Error deleting domain";
        }
    }
}

// Handle domain toggle
if (isset($_GET['toggle_domain']) && isset($_SESSION['logged_in'])) {
    $domainId = $_GET['toggle_domain'];
    if (isset($config['domains'])) {
        foreach ($config['domains'] as &$domain) {
            if ($domain['id'] === $domainId) {
                $domain['enabled'] = !$domain['enabled'];
                break;
            }
        }
        
        if (saveConfig($config)) {
            $success = "Domain status changed successfully!";
        } else {
            $error = "Error changing domain status";
        }
    }
}

// Handle quick add domain from browser
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['quick_add_domain']) && isset($_SESSION['logged_in'])) {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $error = "Invalid request";
    } else {
        $recordType = strtoupper($_POST['record_type'] ?? 'A');
        $recordType = $recordType === 'AAAA' ? 'AAAA' : 'A';
        $domain = [
            'id' => uniqid(),
            'zone_id' => trim($_POST['zone_id']),
            'record_id' => trim($_POST['record_id']),
            'name' => trim($_POST['name']),
            'type' => $recordType,
            'proxied' => isset($_POST['proxied']) && $_POST['proxied'] === '1',
            'enabled' => true
        ];
        
        if (!isset($config['domains'])) {
            $config['domains'] = [];
        }
        
        $config['domains'][] = $domain;
        
        if (saveConfig($config)) {
            $success = "Domain '" . htmlspecialchars($domain['name']) . "' added successfully!";
        } else {
            $error = "Error adding domain";
        }
    }
}

// Generate CSRF token for logged-in users
if (isset($_SESSION['logged_in']) && !isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$currentIPs = [
    'A' => getCurrentIP('A'),
    'AAAA' => getCurrentIP('AAAA')
];
$intervalOptions = getIntervalOptions();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= isset($_SESSION['logged_in']) ? 'Cloudflare DynDNS Panel' : 'Login' ?></title>
    <link rel="icon" href="img/favicon.ico" type="image/x-icon">
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
            max-width: 1000px;
            margin: 0 auto;
        }

        .login-container {
            max-width: 500px;
            margin: 50px auto;
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

        .header p {
            color: #666;
            font-size: 14px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
        }

        .form-group input, .form-group select {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s ease;
        }

        .form-group input:focus, .form-group select:focus {
            outline: none;
            border-color: #667eea;
        }

        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .checkbox-group input[type="checkbox"] {
            width: auto;
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
            transition: transform 0.2s ease;
            text-decoration: none;
            display: inline-block;
        }

        .btn:hover {
            transform: translateY(-2px);
        }

        .btn-full {
            width: 100%;
        }

        .btn-small {
            padding: 8px 16px;
            font-size: 14px;
        }

        .btn-danger {
            background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
        }

        .btn-success {
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
        }

        .btn-secondary {
            background: #6c757d;
        }

        .alert {
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-weight: 500;
        }

        .alert-error {
            background: #fee;
            color: #c33;
            border: 1px solid #fcc;
        }

        .alert-success {
            background: #efe;
            color: #363;
            border: 1px solid #cfc;
        }

        .info-box {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
        }

        .info-box h3 {
            color: #495057;
            margin-bottom: 10px;
        }

        .info-box p {
            color: #6c757d;
            margin-bottom: 5px;
        }

        .domains-section {
            margin-top: 40px;
        }

        .domain-card {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .domain-info h4 {
            color: #333;
            margin-bottom: 5px;
        }

        .domain-info p {
            color: #666;
            font-size: 14px;
            margin-bottom: 2px;
        }

        .domain-actions {
            display: flex;
            gap: 10px;
        }

        .status-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }

        .status-enabled {
            background: #d4edda;
            color: #155724;
        }

        .status-disabled {
            background: #f8d7da;
            color: #721c24;
        }

        .status-proxied {
            background: #fff3cd;
            color: #856404;
        }

        .add-domain-form {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin-top: 20px;
        }

        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }

        .logout-link {
            text-align: center;
            margin-top: 30px;
        }

        .logout-link a {
            color: #dc3545;
            text-decoration: none;
            font-size: 14px;
        }

        .logout-link a:hover {
            text-decoration: underline;
        }

        .zones-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .zone-card {
            background: #fff;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
        }

        .zone-card h4 {
            color: #333;
            margin-bottom: 10px;
        }

        .records-container {
            margin-top: 15px;
        }

        .records-list {
            max-height: 300px;
            overflow-y: auto;
        }

        .record-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            border: 1px solid #e9ecef;
            border-radius: 4px;
            margin-bottom: 8px;
            background: #f8f9fa;
        }

        .record-info {
            flex: 1;
        }

        .record-info strong {
            color: #333;
        }

        .record-info small {
            color: #666;
        }

        .cron-info {
            background: #e3f2fd;
            border: 1px solid #bbdefb;
            border-radius: 8px;
            padding: 15px;
            margin-top: 15px;
        }

        .cron-command {
            background: #263238;
            color: #fff;
            padding: 10px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 14px;
            margin: 10px 0;
            word-break: break-all;
        }

        .copy-btn {
            background: #28a745;
            color: white;
            border: none;
            padding: 4px 8px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            margin-left: 10px;
        }

        hr {
            border: none;
            border-top: 1px solid #dee2e6;
            margin: 30px 0;
        }

        @media (max-width: 768px) {
            .container {
                padding: 20px;
            }
            
            .form-row {
                grid-template-columns: 1fr;
            }
            
            .domain-card {
                flex-direction: column;
                align-items: flex-start;
                gap: 15px;
            }
            
            .domain-actions {
                width: 100%;
                justify-content: flex-end;
            }
        }
    </style>
</head>
<body>
    <?php if (!isset($_SESSION['logged_in'])): ?>
        <!-- Login Form -->
        <div class="container login-container">
            <div class="header">
                <h1>🔐 Login</h1>
                <p>Sign in to access the DynDNS Panel</p>
            </div>

            <?php if ($error): ?>
                <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>

            <!-- Default password hint -->
            <?php if ($config['password'] === password_hash('changeme', PASSWORD_DEFAULT) || password_verify('changeme', $config['password'])): ?>
                <div class="alert" style="background: #fff3cd; color: #856404; border: 1px solid #ffeaa7;">
                    <strong>⚠️ Initial Setup:</strong><br>
                    Default password: <code>changeme</code><br>
                    <small>Please change the password after first login!</small>
                </div>
            <?php endif; ?>

            <form method="POST">
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit" name="login" class="btn btn-full">Sign In</button>
            </form>
        </div>

    <?php else: ?>
        <!-- Dashboard -->
        <div class="container">
            <div class="header">
                <h1>☁️ Cloudflare DynDNS Panel</h1>
                <p>Manage your dynamic DNS settings</p>
            </div>

            <?php if ($error): ?>
                <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>

            <?php if ($success): ?>
                <div class="alert alert-success"><?= htmlspecialchars($success) ?></div>
            <?php endif; ?>

            <!-- Current IP Info -->
            <div class="info-box">
                <h3>📍 Current IP Addresses</h3>
                <?php foreach ($currentIPs as $type => $ipValue): ?>
                    <p>
                        <strong><?= $type === 'AAAA' ? 'IPv6' : 'IPv4' ?>:</strong>
                        <?php if ($ipValue): ?>
                            <?= htmlspecialchars($ipValue) ?>
                        <?php else: ?>
                            <span style="color:#dc3545;">Unavailable</span>
                        <?php endif; ?>
                    </p>
                <?php endforeach; ?>
                <p>Only available addresses are used for DNS updates</p>
            </div>

            <!-- API Token Configuration -->
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                
                <div class="form-group">
                    <label for="api_token">🔑 Cloudflare API Token</label>
                    <input type="password" id="api_token" name="api_token" 
                           value="<?= htmlspecialchars($config['api_token']) ?>" 
                           placeholder="Enter Cloudflare API Token">
                </div>

                <button type="submit" name="save_token" class="btn">💾 Save API Token</button>
            </form>

            <!-- Update Interval Configuration -->
            <hr>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                
                <div class="form-group">
                    <label for="update_interval">⏰ Automatic Update Interval</label>
                    <select id="update_interval" name="update_interval">
                        <?php foreach ($intervalOptions as $value => $label): ?>
                            <option value="<?= $value ?>" <?= $config['update_interval'] === $value ? 'selected' : '' ?>>
                                <?= htmlspecialchars($label) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <button type="submit" name="save_interval" class="btn">⏰ Save Update Interval</button>
                
                <?php if ($config['update_interval'] !== 'manual'): ?>
                    <div class="cron-info">
                        <h4>📋 Cron Job Setup</h4>
                        <p>Add this line to your crontab to enable automatic updates:</p>
                        <div class="cron-command" id="cron-command">
                            <?= htmlspecialchars(generateCronCommand($config['update_interval'], 'auto_update.php')) ?>
                            <button type="button" class="copy-btn" onclick="copyToClipboard('cron-command')">Copy</button>
                        </div>
                        <p><small>Run <code>crontab -e</code> and paste the command above.</small></p>
                    </div>
                <?php endif; ?>
            </form>

            <!-- Domains Section -->
            <div class="domains-section">
                <h2>🌐 Managed Domains</h2>
                
                <?php if (isset($config['domains']) && !empty($config['domains'])): ?>
                    <?php foreach ($config['domains'] as $domain): ?>
                        <div class="domain-card">
                            <div class="domain-info">
                                <h4><?= htmlspecialchars($domain['name']) ?></h4>
                                <p>Zone ID: <?= htmlspecialchars($domain['zone_id']) ?></p>
                                <p>Record ID: <?= htmlspecialchars($domain['record_id']) ?></p>
                                <p>Record Type: <?= htmlspecialchars($domain['type'] ?? 'A') ?></p>
                                <div style="margin-top: 8px;">
                                    <span class="status-badge <?= $domain['enabled'] ? 'status-enabled' : 'status-disabled' ?>">
                                        <?= $domain['enabled'] ? 'Active' : 'Disabled' ?>
                                    </span>
                                    <?php if ($domain['proxied']): ?>
                                        <span class="status-badge status-proxied">Proxied</span>
                                    <?php endif; ?>
                                </div>
                            </div>
                            <div class="domain-actions">
                                <a href="?toggle_domain=<?= $domain['id'] ?>" class="btn btn-small btn-secondary">
                                    <?= $domain['enabled'] ? 'Disable' : 'Enable' ?>
                                </a>
                                <a href="edit_domain.php?id=<?= $domain['id'] ?>" class="btn btn-small btn-secondary">Edit</a>
                                <a href="update.php?domain=<?= $domain['id'] ?>" class="btn btn-small btn-success">Update</a>
                                <a href="?delete_domain=<?= $domain['id'] ?>" class="btn btn-small btn-danger" 
                                   onclick="return confirm('Really delete domain?')">Delete</a>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php else: ?>
                    <p>No domains configured yet.</p>
                <?php endif; ?>

                <!-- Add Domain Form -->
                <div class="add-domain-form">
                    <h3>➕ Add New Domain</h3>
                    
                    <!-- Domain Browser -->
                    <?php if (!empty($config['api_token'])): ?>
                        <div style="margin-bottom: 30px;">
                            <h4>🔍 Domain Browser (recommended)</h4>
                            <p style="color: #666; margin-bottom: 15px;">Browse your Cloudflare domains and add them with one click:</p>
                            
                            <div id="domain-browser">
                                <button type="button" onclick="loadZones()" class="btn btn-secondary" id="load-zones-btn">
                                    🌐 Load My Domains
                                </button>
                                <div id="zones-container" style="margin-top: 20px;"></div>
                            </div>
                        </div>
                        
                        <hr style="margin: 30px 0; border: none; border-top: 1px solid #dee2e6;">
                        
                        <h4>📝 Add Manually</h4>
                        <p style="color: #666; margin-bottom: 15px;">Or add a domain manually if you already know the IDs:</p>
                    <?php endif; ?>
                    
                    <form method="POST">
                        <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                        
                        <div class="form-row">
                            <div class="form-group">
                                <label for="zone_id">Zone ID</label>
                                <input type="text" id="zone_id" name="zone_id" 
                                       placeholder="Cloudflare Zone ID" required>
                            </div>
                            <div class="form-group">
                                <label for="record_id">Record ID</label>
                                <input type="text" id="record_id" name="record_id" 
                                       placeholder="DNS Record ID" required>
                            </div>
                        </div>
                        
                        <div class="form-group">
                            <label for="domain_name">Domain Name</label>
                            <input type="text" id="domain_name" name="domain_name" 
                                   placeholder="e.g. dyn.example.com" required>
                        </div>

                        <div class="form-group">
                            <label for="record_type">Record Type</label>
                            <select id="record_type" name="record_type">
                                <option value="A">A (IPv4)</option>
                                <option value="AAAA">AAAA (IPv6)</option>
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <div class="checkbox-group">
                                <input type="checkbox" id="proxied" name="proxied">
                                <label for="proxied">Route domain through Cloudflare Proxy</label>
                            </div>
                        </div>

                        <button type="submit" name="add_domain" class="btn">➕ Add Domain</button>
                    </form>
                </div>
            </div>

            <!-- Actions -->
            <div style="margin-top: 40px; display: flex; gap: 15px; justify-content: center; flex-wrap: wrap;">
                <a href="update.php" class="btn btn-success">🔄 Update All Active Domains</a>
                <a href="logs.php" class="btn btn-secondary">📊 View Update Logs</a>
                <a href="change_password.php" class="btn btn-secondary">🔑 Change Password</a>
            </div>

            <div class="logout-link">
                <a href="?logout=1">Sign Out</a>
            </div>
        </div>
    <?php endif; ?>
    
    <script>
let zonesData = [];

async function loadZones() {
    const btn = document.getElementById('load-zones-btn');
    const container = document.getElementById('zones-container');
    
    btn.textContent = '⏳ Loading...';
    btn.disabled = true;
    
    try {
        const response = await fetch('api_helper.php?action=get_zones');
        const data = await response.json();
        
        if (data.success) {
            zonesData = data.zones;
            displayZones(data.zones);
        } else {
            container.innerHTML = `<div class="alert alert-error">Error: ${data.error}</div>`;
        }
    } catch (error) {
        container.innerHTML = `<div class="alert alert-error">Network error: ${error.message}</div>`;
    }
    
    btn.textContent = '🔄 Reload';
    btn.disabled = false;
}

function displayZones(zones) {
    const container = document.getElementById('zones-container');
    
    if (zones.length === 0) {
        container.innerHTML = '<p>No domains found.</p>';
        return;
    }
    
    let html = '<div class="zones-grid">';
    
    zones.forEach(zone => {
        html += `
            <div class="zone-card">
                <h4>${zone.name}</h4>
                <p><small>Zone ID: ${zone.id}</small></p>
                <button type="button" onclick="loadRecords('${zone.id}', '${zone.name}')" 
                        class="btn btn-small btn-secondary">
                    📋 Show DNS Records
                </button>
                <div id="records-${zone.id}" class="records-container"></div>
            </div>
        `;
    });
    
    html += '</div>';
    container.innerHTML = html;
}

async function loadRecords(zoneId, zoneName) {
    const container = document.getElementById(`records-${zoneId}`);
    container.innerHTML = '<p>⏳ Loading records...</p>';
    
    try {
        const response = await fetch(`api_helper.php?action=get_records&zone_id=${zoneId}`);
        const data = await response.json();
        
        if (data.success) {
            displayRecords(data.records, zoneId, zoneName);
        } else {
            container.innerHTML = `<div class="alert alert-error">Error: ${data.error}</div>`;
        }
    } catch (error) {
        container.innerHTML = `<div class="alert alert-error">Network error: ${error.message}</div>`;
    }
}

function displayRecords(records, zoneId, zoneName) {
    const container = document.getElementById(`records-${zoneId}`);
    
    if (records.length === 0) {
        container.innerHTML = '<p><small>No A or AAAA records found.</small></p>';
        return;
    }
    
    let html = '<div class="records-list">';
    
    records.forEach(record => {
        html += `
            <div class="record-item">
                <div class="record-info">
                    <strong>${record.name}</strong><br>
                    <small>Type: ${record.type} | Content: ${record.content} | Proxied: ${record.proxied ? 'Yes' : 'No'}</small>
                </div>
                <form method="POST" style="display: inline;">
                    <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                    <input type="hidden" name="zone_id" value="${zoneId}">
                    <input type="hidden" name="record_id" value="${record.id}">
                    <input type="hidden" name="name" value="${record.name}">
                    <input type="hidden" name="record_type" value="${record.type}">
                    <input type="hidden" name="proxied" value="${record.proxied ? '1' : '0'}">
                    <button type="submit" name="quick_add_domain" class="btn btn-small btn-success">
                        ➕ Add
                    </button>
                </form>
            </div>
        `;
    });
    
    html += '</div>';
    container.innerHTML = html;
}

function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    const text = element.textContent.trim();
    
    navigator.clipboard.writeText(text).then(() => {
        const btn = element.querySelector('.copy-btn');
        const originalText = btn.textContent;
        btn.textContent = 'Copied!';
        btn.style.background = '#28a745';
        
        setTimeout(() => {
            btn.textContent = originalText;
            btn.style.background = '#28a745';
        }, 2000);
    }).catch(() => {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        
        const btn = element.querySelector('.copy-btn');
        const originalText = btn.textContent;
        btn.textContent = 'Copied!';
        
        setTimeout(() => {
            btn.textContent = originalText;
        }, 2000);
    });
}
</script>
</body>
</html>
