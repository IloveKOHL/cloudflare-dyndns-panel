<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/cloudflare_api.php';

startSecureSession();
$cspNonce = cspNonce();

// Get current IP
function getCurrentIP() {
    $context = stream_context_create(['http' => ['timeout' => 10, 'max_redirects' => 0]]);
    $ip = @file_get_contents('https://api.ipify.org', false, $context, 0, 64);
    $ip = $ip === false ? '' : trim($ip);
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false ? $ip : 'Unknown';
}

// Generate cron command based on interval
function generateCronCommand($interval, $scriptPath) {
    $phpPath = '/usr/bin/php'; // Adjust if needed
    $fullPath = realpath($scriptPath);
    if ($fullPath === false) {
        return null;
    }
    $quotedPath = escapeshellarg($fullPath);
    $dataDirectory = getenv('DYNDNS_DATA_DIR');
    $environment = $dataDirectory !== false && trim($dataDirectory) !== ''
        ? 'DYNDNS_DATA_DIR=' . escapeshellarg(trim($dataDirectory)) . ' '
        : '';
    
    switch ($interval) {
        case '5min':
            return "*/5 * * * * {$environment}$phpPath $quotedPath";
        case '15min':
            return "*/15 * * * * {$environment}$phpPath $quotedPath";
        case '30min':
            return "*/30 * * * * {$environment}$phpPath $quotedPath";
        case '1hour':
            return "0 * * * * {$environment}$phpPath $quotedPath";
        case '6hours':
            return "0 */6 * * * {$environment}$phpPath $quotedPath";
        case '12hours':
            return "0 */12 * * * {$environment}$phpPath $quotedPath";
        case 'daily':
            return "0 0 * * * {$environment}$phpPath $quotedPath";
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

$config = loadConfig();
$error = '';
$success = '';

// Handle login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $retryAfter = loginRetryAfter();
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        $error = "Invalid request";
    } elseif ($retryAfter > 0) {
        http_response_code(429);
        header('Retry-After: ' . $retryAfter);
        $error = "Too many failed attempts. Try again later.";
    } elseif (isset($_POST['password']) && is_string($_POST['password']) && password_verify($_POST['password'], $config['password'])) {
        clearLoginFailures();
        session_regenerate_id(true);
        $_SESSION['logged_in'] = true;
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        header("Location: index.php");
        exit;
    } else {
        recordLoginFailure();
        $error = "Invalid password";
    }
}

// Handle logout
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['logout']) && isLoggedIn()) {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        http_response_code(400);
        $error = "Invalid request";
    } else {
        logoutSession();
        header("Location: index.php");
        exit;
    }
}

if (isLoggedIn()) {
    requirePasswordChangeComplete($config);
}

// Handle API token save
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_token']) && isLoggedIn()) {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        $error = "Invalid request";
    } elseif (($environmentToken = getenv('CLOUDFLARE_API_TOKEN')) !== false && trim($environmentToken) !== '') {
        $error = "The API token is managed by the CLOUDFLARE_API_TOKEN environment variable.";
    } else {
        $token = isset($_POST['api_token']) && is_string($_POST['api_token']) ? trim($_POST['api_token']) : '';
        if ($token === '') {
            $error = "Enter a new API token; the existing token was left unchanged.";
        } elseif (strlen($token) > 512 || preg_match('/[\r\n]/', $token)) {
            $error = "Invalid API token format.";
        } else {
            $verification = cloudflareRequest('GET', '/user/tokens/verify', $token);
            $active = !empty($verification['success'])
                && isset($verification['result']['status'])
                && $verification['result']['status'] === 'active';
            if (!$active) {
                $error = "Cloudflare rejected the API token.";
            } else {
                $config['api_token'] = $token;
                if (saveConfig($config)) {
                    $success = "API Token verified and saved successfully!";
                } else {
                    $error = "Error saving API Token";
                }
            }
        }
    }
}

// Handle update interval save
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_interval']) && isLoggedIn()) {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        $error = "Invalid request";
    } else {
        $interval = isset($_POST['update_interval']) ? (string) $_POST['update_interval'] : '';
        if (!in_array($interval, allowedUpdateIntervals(), true)) {
            $error = "Invalid update interval";
        } else {
            $config['update_interval'] = $interval;
            if (saveConfig($config)) {
                $success = "Update interval saved successfully!";
            } else {
                $error = "Error saving update interval";
            }
        }
    }
}

// Handle domain addition
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_domain']) && isLoggedIn()) {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        $error = "Invalid request";
    } else {
        try {
            $domain = validatedDomainInput($_POST);
            $domain['id'] = bin2hex(random_bytes(16));
            $domain['enabled'] = true;
            $config['domains'][] = $domain;
            if (saveConfig($config)) {
                $success = "Domain added successfully!";
            } else {
                array_pop($config['domains']);
                $error = "Error adding domain";
            }
        } catch (InvalidArgumentException $exception) {
            $error = $exception->getMessage();
        }
    }
}

// Handle domain deletion and toggle via CSRF-protected POST requests.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['domain_action']) && isLoggedIn()) {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        $error = "Invalid request";
    } else {
        $domainId = isset($_POST['domain_id']) ? (string) $_POST['domain_id'] : '';
        $action = (string) $_POST['domain_action'];
        if (!preg_match('/^[a-f0-9]{13,32}$/i', $domainId) || !in_array($action, ['delete', 'toggle'], true)) {
            $error = "Invalid domain action";
        } elseif ($action === 'delete') {
            $originalCount = count($config['domains']);
            $config['domains'] = array_values(array_filter($config['domains'], static function ($domain) use ($domainId) {
                return !isset($domain['id']) || !hash_equals((string) $domain['id'], $domainId);
            }));
            if (count($config['domains']) === $originalCount) {
                $error = "Domain not found";
            } elseif (saveConfig($config)) {
                $success = "Domain deleted successfully!";
            } else {
                $error = "Error deleting domain";
            }
        } else {
            $found = false;
            foreach ($config['domains'] as &$domain) {
                if (isset($domain['id']) && hash_equals((string) $domain['id'], $domainId)) {
                    $domain['enabled'] = empty($domain['enabled']);
                    $found = true;
                    break;
                }
            }
            unset($domain);
            if (!$found) {
                $error = "Domain not found";
            } elseif (saveConfig($config)) {
                $success = "Domain status changed successfully!";
            } else {
                $error = "Error changing domain status";
            }
        }
    }
}

// Handle quick add domain from browser
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['quick_add_domain']) && isLoggedIn()) {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        $error = "Invalid request";
    } else {
        try {
            $domain = validatedDomainInput($_POST);
            $domain['id'] = bin2hex(random_bytes(16));
            $domain['enabled'] = true;
            $config['domains'][] = $domain;
            if (saveConfig($config)) {
                $success = "Domain '" . $domain['name'] . "' added successfully!";
            } else {
                array_pop($config['domains']);
                $error = "Error adding domain";
            }
        } catch (InvalidArgumentException $exception) {
            $error = $exception->getMessage();
        }
    }
}

// Always have a CSRF token, including on the login form.
csrfToken();

$currentIP = isLoggedIn() ? getCurrentIP() : 'Unknown';
$intervalOptions = getIntervalOptions();
$hasApiToken = configuredApiToken($config) !== '';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= isLoggedIn() ? 'Cloudflare DynDNS Panel' : 'Login' ?></title>
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
    <?php if (!isLoggedIn()): ?>
        <!-- Login Form -->
        <div class="container login-container">
            <div class="header">
                <h1>🔐 Login</h1>
                <p>Sign in to access the DynDNS Panel</p>
            </div>

            <?php if ($error): ?>
                <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>

            <?php if (!empty($config['must_change_password'])): ?>
                <div class="alert" style="background: #fff3cd; color: #856404; border: 1px solid #ffeaa7;">
                    <strong>⚠️ Initial Setup:</strong><br>
                    <small>Use the deployment password. If none was supplied, read the generated value from <code>initial_password.txt</code> in the protected data directory. It must be changed before the panel can be used.</small>
                </div>
            <?php endif; ?>

            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrfToken(), ENT_QUOTES, 'UTF-8') ?>">
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
                <h3>📍 Current IP Address</h3>
                <p><strong><?= htmlspecialchars($currentIP) ?></strong></p>
                <p>This IP will be used for DNS updates</p>
            </div>

            <!-- API Token Configuration -->
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrfToken(), ENT_QUOTES, 'UTF-8') ?>">
                
                <div class="form-group">
                    <label for="api_token">🔑 Cloudflare API Token</label>
                    <input type="password" id="api_token" name="api_token" 
                           value="" autocomplete="new-password"
                           placeholder="<?= $hasApiToken ? 'Token configured — enter a replacement' : 'Enter Cloudflare API Token' ?>">
                </div>

                <button type="submit" name="save_token" class="btn" <?= getenv('CLOUDFLARE_API_TOKEN') ? 'disabled' : '' ?>>💾 Verify &amp; Save API Token</button>
            </form>

            <!-- Update Interval Configuration -->
            <hr>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrfToken(), ENT_QUOTES, 'UTF-8') ?>">
                
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
                            <button type="button" class="copy-btn" data-copy-target="cron-command">Copy</button>
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
                                <form method="POST">
                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrfToken(), ENT_QUOTES, 'UTF-8') ?>">
                                    <input type="hidden" name="domain_id" value="<?= htmlspecialchars((string) $domain['id'], ENT_QUOTES, 'UTF-8') ?>">
                                    <button type="submit" name="domain_action" value="toggle" class="btn btn-small btn-secondary">
                                        <?= $domain['enabled'] ? 'Disable' : 'Enable' ?>
                                    </button>
                                </form>
                                <a href="edit_domain.php?id=<?= rawurlencode((string) $domain['id']) ?>" class="btn btn-small btn-secondary">Edit</a>
                                <form method="POST" action="update.php">
                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrfToken(), ENT_QUOTES, 'UTF-8') ?>">
                                    <input type="hidden" name="domain" value="<?= htmlspecialchars((string) $domain['id'], ENT_QUOTES, 'UTF-8') ?>">
                                    <button type="submit" class="btn btn-small btn-success">Update</button>
                                </form>
                                <form method="POST" data-confirm="Really delete domain?">
                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrfToken(), ENT_QUOTES, 'UTF-8') ?>">
                                    <input type="hidden" name="domain_id" value="<?= htmlspecialchars((string) $domain['id'], ENT_QUOTES, 'UTF-8') ?>">
                                    <button type="submit" name="domain_action" value="delete" class="btn btn-small btn-danger">Delete</button>
                                </form>
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
                    <?php if ($hasApiToken): ?>
                        <div style="margin-bottom: 30px;">
                            <h4>🔍 Domain Browser (recommended)</h4>
                            <p style="color: #666; margin-bottom: 15px;">Browse your Cloudflare domains and add them with one click:</p>
                            
                            <div id="domain-browser">
                                <button type="button" class="btn btn-secondary" id="load-zones-btn">
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
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrfToken(), ENT_QUOTES, 'UTF-8') ?>">
                        
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
                <form method="POST" action="update.php">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrfToken(), ENT_QUOTES, 'UTF-8') ?>">
                    <button type="submit" class="btn btn-success">🔄 Update All Active Domains</button>
                </form>
                <a href="logs.php" class="btn btn-secondary">📊 View Update Logs</a>
                <a href="change_password.php" class="btn btn-secondary">🔑 Change Password</a>
            </div>

            <div class="logout-link">
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrfToken(), ENT_QUOTES, 'UTF-8') ?>">
                    <button type="submit" name="logout" class="btn btn-small btn-danger">Sign Out</button>
                </form>
            </div>
        </div>
    <?php endif; ?>
    
    <script nonce="<?= htmlspecialchars($cspNonce, ENT_QUOTES, 'UTF-8') ?>">
let zonesData = [];
const csrfToken = <?= json_encode(csrfToken(), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;

function showMessage(container, message, isError = false) {
    const element = document.createElement('div');
    if (isError) {
        element.className = 'alert alert-error';
    }
    element.textContent = message;
    container.replaceChildren(element);
}

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
            showMessage(container, `Error: ${data.error}`, true);
        }
    } catch (error) {
        showMessage(container, `Network error: ${error.message}`, true);
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
    
    const grid = document.createElement('div');
    grid.className = 'zones-grid';
    zones.forEach(zone => {
        const card = document.createElement('div');
        card.className = 'zone-card';
        const heading = document.createElement('h4');
        heading.textContent = zone.name;
        const details = document.createElement('p');
        const small = document.createElement('small');
        small.textContent = `Zone ID: ${zone.id}`;
        details.appendChild(small);
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'btn btn-small btn-secondary';
        button.textContent = '📋 Show A Records';
        button.addEventListener('click', () => loadRecords(zone.id));
        const records = document.createElement('div');
        records.id = `records-${zone.id}`;
        records.className = 'records-container';
        card.append(heading, details, button, records);
        grid.appendChild(card);
    });
    container.replaceChildren(grid);
}

async function loadRecords(zoneId) {
    const container = document.getElementById(`records-${zoneId}`);
    showMessage(container, '⏳ Loading records...');
    
    try {
        const response = await fetch(`api_helper.php?action=get_records&zone_id=${encodeURIComponent(zoneId)}`);
        const data = await response.json();
        
        if (data.success) {
            displayRecords(data.records, zoneId);
        } else {
            showMessage(container, `Error: ${data.error}`, true);
        }
    } catch (error) {
        showMessage(container, `Network error: ${error.message}`, true);
    }
}

function hiddenInput(name, value) {
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = name;
    input.value = value;
    return input;
}

function displayRecords(records, zoneId) {
    const container = document.getElementById(`records-${zoneId}`);
    
    if (records.length === 0) {
        container.innerHTML = '<p><small>No A records found.</small></p>';
        return;
    }
    
    const list = document.createElement('div');
    list.className = 'records-list';
    records.forEach(record => {
        const item = document.createElement('div');
        item.className = 'record-item';
        const info = document.createElement('div');
        info.className = 'record-info';
        const name = document.createElement('strong');
        name.textContent = record.name;
        const lineBreak = document.createElement('br');
        const details = document.createElement('small');
        details.textContent = `IP: ${record.content} | Proxied: ${record.proxied ? 'Yes' : 'No'}`;
        info.append(name, lineBreak, details);

        const form = document.createElement('form');
        form.method = 'POST';
        form.append(
            hiddenInput('csrf_token', csrfToken),
            hiddenInput('zone_id', zoneId),
            hiddenInput('record_id', record.id),
            hiddenInput('name', record.name),
            hiddenInput('proxied', record.proxied ? '1' : '0')
        );
        const add = document.createElement('button');
        add.type = 'submit';
        add.name = 'quick_add_domain';
        add.className = 'btn btn-small btn-success';
        add.textContent = '➕ Add';
        form.appendChild(add);
        item.append(info, form);
        list.appendChild(item);
    });
    container.replaceChildren(list);
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

const loadZonesButton = document.getElementById('load-zones-btn');
if (loadZonesButton) {
    loadZonesButton.addEventListener('click', loadZones);
}
document.querySelectorAll('[data-copy-target]').forEach(button => {
    button.addEventListener('click', () => copyToClipboard(button.dataset.copyTarget));
});
document.querySelectorAll('form[data-confirm]').forEach(form => {
    form.addEventListener('submit', event => {
        if (!window.confirm(form.dataset.confirm)) {
            event.preventDefault();
        }
    });
});
</script>
</body>
</html>
