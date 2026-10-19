<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

startSecureSession();
requireLogin();

$config = loadConfig();
requirePasswordChangeComplete($config);
$error = '';
$success = '';
$domain = null;

// Check if domain ID is provided
if (!isset($_GET['id'])) {
    header("Location: index.php");
    exit;
}

$domainId = (string) $_GET['id'];
if (!preg_match('/^[a-f0-9]{13,32}$/i', $domainId)) {
    http_response_code(400);
    exit('Invalid domain ID');
}

// Find the domain in the config
foreach ($config['domains'] as $key => $d) {
    if (isset($d['id']) && is_string($d['id']) && hash_equals($d['id'], $domainId)) {
        $domain = $d;
        $domainIndex = $key;
        break;
    }
}

// If domain not found, redirect to index
if (!$domain) {
    header("Location: index.php");
    exit;
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_domain'])) {
    // CSRF protection
    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        $error = "Invalid request";
    } else {
        try {
            $validated = validatedDomainInput($_POST);
            $config['domains'][$domainIndex] = array_merge($config['domains'][$domainIndex], $validated);
            if (saveConfig($config)) {
                $success = "Domain updated successfully!";
                $domain = $config['domains'][$domainIndex];
            } else {
                $error = "Error updating domain";
            }
        } catch (InvalidArgumentException $exception) {
            $error = $exception->getMessage();
        }
    }
}

csrfToken();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Domain - Cloudflare DynDNS</title>
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
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            padding: 40px;
            width: 100%;
            max-width: 600px;
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

        .form-group input {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s ease;
        }

        .form-group input:focus {
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

        .btn-secondary {
            background: #6c757d;
            margin-top: 10px;
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

        .back-link {
            text-align: center;
            margin-top: 20px;
        }

        .back-link a {
            color: #667eea;
            text-decoration: none;
            font-size: 14px;
        }

        .back-link a:hover {
            text-decoration: underline;
        }

        .domain-info {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
        }

        .domain-info h3 {
            color: #495057;
            margin-bottom: 10px;
            font-size: 18px;
        }

        .domain-info p {
            color: #6c757d;
            margin-bottom: 5px;
            font-size: 14px;
        }

        .buttons-row {
            display: flex;
            gap: 10px;
            margin-top: 20px;
        }

        .buttons-row .btn {
            flex: 1;
        }

        @media (max-width: 768px) {
            .container {
                padding: 20px;
            }
            
            .buttons-row {
                flex-direction: column;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>✏️ Edit Domain</h1>
            <p>Update domain configuration</p>
        </div>

        <?php if ($error): ?>
            <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <?php if ($success): ?>
            <div class="alert alert-success"><?= htmlspecialchars($success) ?></div>
        <?php endif; ?>

        <div class="domain-info">
            <h3><?= htmlspecialchars($domain['name']) ?></h3>
            <p><strong>Status:</strong> <?= $domain['enabled'] ? 'Active' : 'Disabled' ?></p>
            <p><strong>Proxied:</strong> <?= $domain['proxied'] ? 'Yes' : 'No' ?></p>
        </div>

        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrfToken(), ENT_QUOTES, 'UTF-8') ?>">
            
            <div class="form-group">
                <label for="zone_id">Zone ID</label>
                <input type="text" id="zone_id" name="zone_id" 
                       value="<?= htmlspecialchars($domain['zone_id'], ENT_QUOTES, 'UTF-8') ?>" required>
            </div>

            <div class="form-group">
                <label for="record_id">Record ID</label>
                <input type="text" id="record_id" name="record_id" 
                       value="<?= htmlspecialchars($domain['record_id'], ENT_QUOTES, 'UTF-8') ?>" required>
            </div>

            <div class="form-group">
                <label for="domain_name">Domain Name</label>
                <input type="text" id="domain_name" name="domain_name" 
                       value="<?= htmlspecialchars($domain['name'], ENT_QUOTES, 'UTF-8') ?>" required>
            </div>

            <div class="form-group">
                <div class="checkbox-group">
                    <input type="checkbox" id="proxied" name="proxied" 
                           <?= $domain['proxied'] ? 'checked' : '' ?>>
                    <label for="proxied">Route domain through Cloudflare Proxy</label>
                </div>
            </div>

            <div class="buttons-row">
                <button type="submit" name="save_domain" class="btn">💾 Save Changes</button>
                <a href="index.php" class="btn btn-secondary">Cancel</a>
            </div>
        </form>

        <div class="back-link">
            <a href="index.php">← Back to Dashboard</a>
        </div>
    </div>
</body>
</html>
