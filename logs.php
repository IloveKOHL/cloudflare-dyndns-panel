<?php
session_start();
if (!isset($_SESSION['logged_in'])) {
    die("Not logged in!");
}

// Load update logs
function loadLogs() {
    if (!file_exists('update_log.json')) {
        return [];
    }
    return json_decode(file_get_contents('update_log.json'), true) ?: [];
}

// Clear logs
if (isset($_GET['clear']) && isset($_SESSION['logged_in'])) {
    if (file_exists('update_log.json')) {
        unlink('update_log.json');
    }
    header("Location: logs.php");
    exit;
}

$logs = loadLogs();
$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$perPage = 20;
$totalLogs = count($logs);
$totalPages = ceil($totalLogs / $perPage);
$offset = ($page - 1) * $perPage;
$pagedLogs = array_slice($logs, $offset, $perPage);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Update Logs - Cloudflare DynDNS</title>
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

        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
        }

        .header h1 {
            color: #333;
            font-size: 28px;
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
        }

        .btn:hover {
            transform: translateY(-2px);
        }

        .btn-small {
            padding: 8px 16px;
            font-size: 14px;
        }

        .btn-danger {
            background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
        }

        .log-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }

        .log-table th,
        .log-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }

        .log-table th {
            background: #f8f9fa;
            font-weight: 600;
            color: #495057;
        }

        .log-table tr:hover {
            background: #f8f9fa;
        }

        .status-success {
            color: #28a745;
            font-weight: 600;
        }

        .status-error {
            color: #dc3545;
            font-weight: 600;
        }

        .badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }

        .badge-auto {
            background: #e3f2fd;
            color: #1976d2;
        }

        .badge-manual {
            background: #f3e5f5;
            color: #7b1fa2;
        }

        .pagination {
            display: flex;
            justify-content: center;
            gap: 10px;
            margin-top: 20px;
        }

        .pagination a {
            padding: 8px 12px;
            background: #f8f9fa;
            color: #495057;
            text-decoration: none;
            border-radius: 4px;
            border: 1px solid #dee2e6;
        }

        .pagination a:hover {
            background: #e9ecef;
        }

        .pagination .current {
            background: #667eea;
            color: white;
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }

        .stat-number {
            font-size: 24px;
            font-weight: bold;
            color: #667eea;
        }

        .stat-label {
            color: #666;
            font-size: 14px;
            margin-top: 5px;
        }

        .no-logs {
            text-align: center;
            color: #666;
            padding: 40px;
        }

        @media (max-width: 768px) {
            .container {
                padding: 20px;
            }
            
            .header {
                flex-direction: column;
                gap: 15px;
            }
            
            .log-table {
                font-size: 14px;
            }
            
            .log-table th,
            .log-table td {
                padding: 8px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Update Logs</h1>
            <div>
                <a href="index.php" class="btn btn-small">← Back to Dashboard</a>
                <?php if (!empty($logs)): ?>
                    <a href="?clear=1" class="btn btn-small btn-danger" onclick="return confirm('Really clear all logs?')">🗑️ Clear Logs</a>
                <?php endif; ?>
            </div>
        </div>

        <?php if (!empty($logs)): ?>
            <!-- Statistics -->
            <?php
            $successCount = count(array_filter($logs, function($log) { return $log['success']; }));
            $errorCount = count(array_filter($logs, function($log) { return !$log['success']; }));
            $autoCount = count(array_filter($logs, function($log) { return isset($log['automatic']) && $log['automatic']; }));
            $manualCount = count(array_filter($logs, function($log) { return !isset($log['automatic']) || !$log['automatic']; }));
            ?>
            
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number"><?= $totalLogs ?></div>
                    <div class="stat-label">Total Updates</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" style="color: #28a745;"><?= $successCount ?></div>
                    <div class="stat-label">Successful</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" style="color: #dc3545;"><?= $errorCount ?></div>
                    <div class="stat-label">Failed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" style="color: #1976d2;"><?= $autoCount ?></div>
                    <div class="stat-label">Automatic</div>
                </div>
            </div>

            <!-- Logs Table -->
            <table class="log-table">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Domain</th>
                        <th>Record Type</th>
                        <th>IP Address</th>
                        <th>Status</th>
                        <th>Mode</th>
                        <th>Error</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($pagedLogs as $log): ?>
                        <tr>
                            <td><?= htmlspecialchars($log['timestamp']) ?></td>
                            <td><?= htmlspecialchars($log['domain']) ?></td>
                            <td><?= htmlspecialchars($log['record_type'] ?? 'A') ?></td>
                            <td><?= htmlspecialchars($log['ip']) ?></td>
                            <td>
                                <span class="<?= $log['success'] ? 'status-success' : 'status-error' ?>">
                                    <?= $log['success'] ? '✅ Success' : '❌ Failed' ?>
                                </span>
                            </td>
                            <td>
                                <span class="badge <?= (isset($log['automatic']) && $log['automatic']) ? 'badge-auto' : 'badge-manual' ?>">
                                    <?= (isset($log['automatic']) && $log['automatic']) ? 'Auto' : 'Manual' ?>
                                </span>
                            </td>
                            <td><?= htmlspecialchars($log['error'] ?? '') ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>

            <!-- Pagination -->
            <?php if ($totalPages > 1): ?>
                <div class="pagination">
                    <?php if ($page > 1): ?>
                        <a href="?page=<?= $page - 1 ?>">← Previous</a>
                    <?php endif; ?>
                    
                    <?php for ($i = max(1, $page - 2); $i <= min($totalPages, $page + 2); $i++): ?>
                        <a href="?page=<?= $i ?>" class="<?= $i === $page ? 'current' : '' ?>"><?= $i ?></a>
                    <?php endfor; ?>
                    
                    <?php if ($page < $totalPages): ?>
                        <a href="?page=<?= $page + 1 ?>">Next →</a>
                    <?php endif; ?>
                </div>
            <?php endif; ?>

        <?php else: ?>
            <div class="no-logs">
                <h3>📝 No logs yet</h3>
                <p>DNS update logs will appear here after your first update.</p>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>
