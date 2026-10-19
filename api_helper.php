<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/cloudflare_api.php';

startSecureSession();
requireLogin(true);
header('Content-Type: application/json; charset=utf-8');

$config = loadConfig();
requirePasswordChangeComplete($config, true);
$apiToken = configuredApiToken($config);
if ($apiToken === '') {
    echo json_encode(['success' => false, 'error' => 'No API token configured']);
    exit;
}

$action = isset($_GET['action']) ? (string) $_GET['action'] : '';
if ($action === 'get_zones') {
    $response = cloudflareRequest('GET', '/zones?per_page=50', $apiToken);
    if (empty($response['success']) || !isset($response['result']) || !is_array($response['result'])) {
        echo json_encode(['success' => false, 'error' => cloudflareErrors($response)]);
        exit;
    }

    $zones = [];
    foreach ($response['result'] as $zone) {
        if (is_array($zone)
            && isset($zone['id'], $zone['name'])
            && is_string($zone['id'])
            && is_string($zone['name'])
            && validateCloudflareId($zone['id'])
            && validateDomainName($zone['name'])) {
            $zones[] = ['id' => $zone['id'], 'name' => $zone['name']];
        }
    }
    usort($zones, static function (array $left, array $right): int {
        return strcmp($left['name'], $right['name']);
    });
    echo json_encode(['success' => true, 'zones' => $zones]);
    exit;
}

if ($action === 'get_records') {
    $zoneId = isset($_GET['zone_id']) ? trim((string) $_GET['zone_id']) : '';
    if (!validateCloudflareId($zoneId)) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Invalid Zone ID']);
        exit;
    }

    $response = cloudflareRequest('GET', '/zones/' . rawurlencode($zoneId) . '/dns_records?type=A&per_page=100', $apiToken);
    if (empty($response['success']) || !isset($response['result']) || !is_array($response['result'])) {
        echo json_encode(['success' => false, 'error' => cloudflareErrors($response)]);
        exit;
    }

    $records = [];
    foreach ($response['result'] as $record) {
        if (is_array($record)
            && isset($record['id'], $record['name'], $record['content'])
            && is_string($record['id'])
            && is_string($record['name'])
            && is_string($record['content'])
            && validateCloudflareId($record['id'])
            && validateDomainName($record['name'])
            && filter_var($record['content'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            $records[] = [
                'id' => $record['id'],
                'name' => $record['name'],
                'content' => $record['content'],
                'proxied' => !empty($record['proxied']),
            ];
        }
    }
    usort($records, static function (array $left, array $right): int {
        return strcmp($left['name'], $right['name']);
    });
    echo json_encode(['success' => true, 'records' => $records]);
    exit;
}

http_response_code(400);
echo json_encode(['success' => false, 'error' => 'Unknown action']);
