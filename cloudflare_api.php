<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

function cloudflareRequest(string $method, string $path, string $apiToken, ?array $body = null): array
{
    if ($apiToken === '' || preg_match('/[\r\n]/', $apiToken)) {
        return ['success' => false, 'errors' => [['message' => 'Invalid API token']]];
    }

    $headers = [
        'Authorization: Bearer ' . $apiToken,
        'Accept: application/json',
        'User-Agent: CloudflareDynDNSPanel/1.1',
    ];
    $http = [
        'method' => strtoupper($method),
        'header' => $headers,
        'timeout' => 20,
        'ignore_errors' => true,
        'max_redirects' => 0,
    ];

    if ($body !== null) {
        $http['header'][] = 'Content-Type: application/json';
        $http['content'] = json_encode($body, JSON_UNESCAPED_SLASHES);
    }

    $context = stream_context_create([
        'http' => $http,
        'ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true,
            'peer_name' => 'api.cloudflare.com',
            'SNI_enabled' => true,
        ],
    ]);

    $result = @file_get_contents('https://api.cloudflare.com/client/v4' . $path, false, $context, 0, 1048576);
    if ($result === false) {
        return ['success' => false, 'errors' => [['message' => 'Cloudflare network error or timeout']]];
    }

    try {
        $decoded = json_decode($result, true, 64, JSON_THROW_ON_ERROR);
    } catch (JsonException $exception) {
        return ['success' => false, 'errors' => [['message' => 'Invalid Cloudflare API response']]];
    }

    return is_array($decoded)
        ? $decoded
        : ['success' => false, 'errors' => [['message' => 'Invalid Cloudflare API response']]];
}

function getCloudflareZones(string $apiToken): array
{
    $response = cloudflareRequest('GET', '/zones?per_page=50', $apiToken);
    return !empty($response['success']) && isset($response['result']) && is_array($response['result'])
        ? $response['result']
        : [];
}

function getDNSRecords(string $apiToken, string $zoneId): array
{
    if (!validateCloudflareId($zoneId)) {
        return [];
    }
    $response = cloudflareRequest('GET', '/zones/' . rawurlencode($zoneId) . '/dns_records?type=A&per_page=100', $apiToken);
    return !empty($response['success']) && isset($response['result']) && is_array($response['result'])
        ? $response['result']
        : [];
}

function updateDNSRecord(string $apiToken, string $zoneId, string $recordId, string $name, string $ip, bool $proxied = false): array
{
    if (!validateCloudflareId($zoneId) || !validateCloudflareId($recordId) || !validateDomainName($name)) {
        return ['success' => false, 'errors' => [['message' => 'Invalid domain configuration']]];
    }
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
        return ['success' => false, 'errors' => [['message' => 'Invalid IPv4 address']]];
    }

    return cloudflareRequest(
        'PATCH',
        '/zones/' . rawurlencode($zoneId) . '/dns_records/' . rawurlencode($recordId),
        $apiToken,
        [
            'type' => 'A',
            'name' => $name,
            'content' => $ip,
            'proxied' => $proxied,
        ]
    );
}

function cloudflareErrors(array $response): string
{
    if (!isset($response['errors']) || !is_array($response['errors'])) {
        return 'Unknown API error';
    }

    $messages = [];
    foreach ($response['errors'] as $error) {
        if (is_array($error) && isset($error['message']) && is_string($error['message'])) {
            $messages[] = $error['message'];
        }
    }
    return $messages ? implode(', ', $messages) : 'Unknown API error';
}
