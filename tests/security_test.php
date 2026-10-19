<?php
declare(strict_types=1);

$temporary = dirname(__DIR__) . DIRECTORY_SEPARATOR . '.test-data' . DIRECTORY_SEPARATOR . bin2hex(random_bytes(8));
if (!mkdir($temporary, 0700, true) && !is_dir($temporary)) {
    throw new RuntimeException('Unable to create test directory.');
}

putenv('DYNDNS_DATA_DIR=' . $temporary);
putenv('DYNDNS_INITIAL_PASSWORD=correct-horse-battery-staple');

require_once dirname(__DIR__) . '/bootstrap.php';
require_once dirname(__DIR__) . '/cloudflare_api.php';

function assertSecurity($condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$config = loadConfig();
assertSecurity(password_verify('correct-horse-battery-staple', $config['password']), 'initial password is hashed');
assertSecurity(!password_verify('changeme', $config['password']), 'historical default password is rejected');
assertSecurity($config['must_change_password'] === true, 'initial password change is required');
assertSecurity(is_file(dataPath(CONFIG_FILE)), 'configuration is stored in the protected data directory');
if (DIRECTORY_SEPARATOR === '/') {
    assertSecurity((fileperms(dataPath(CONFIG_FILE)) & 0777) === 0600, 'configuration permissions are owner-only');
}

assertSecurity(validateCloudflareId(str_repeat('a', 32)), 'valid Cloudflare ID accepted');
assertSecurity(!validateCloudflareId('../dns_records'), 'path-like Cloudflare ID rejected');
assertSecurity(validateDomainName('dyn.example.com'), 'valid hostname accepted');
assertSecurity(!validateDomainName("example.com\r\nInjected"), 'control characters rejected');

$invalidToken = cloudflareRequest('GET', '/user/tokens/verify', "token\r\nX-Test: injected");
assertSecurity($invalidToken['success'] === false, 'header injection in token rejected before network access');

assertSecurity(logUpdate('dyn.example.com', '192.0.2.1', true), 'log write succeeds');
assertSecurity(count(loadLogs()) === 1, 'log write can be read back');
assertSecurity(clearLogs(), 'logs can be cleared');

$_SERVER['REMOTE_ADDR'] = '192.0.2.99';
for ($attempt = 0; $attempt < 5; $attempt++) {
    recordLoginFailure();
}
assertSecurity(loginRetryAfter() > 0, 'login throttling activates after five failures');
clearLoginFailures();
assertSecurity(loginRetryAfter() === 0, 'successful login can clear throttling state');

putenv('CLOUDFLARE_API_TOKEN=environment-secret');
$config['api_token'] = 'stored-secret';
assertSecurity(saveConfig($config), 'configuration saves with environment token');
$persisted = readJsonData(CONFIG_FILE, []);
assertSecurity($persisted['api_token'] === '', 'environment token is not duplicated on disk');
assertSecurity(configuredApiToken($persisted) === 'environment-secret', 'environment token takes precedence');

$entries = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($temporary, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::CHILD_FIRST
);
foreach ($entries as $entry) {
    if ($entry->isDir() && !$entry->isLink()) {
        rmdir($entry->getPathname());
    } else {
        unlink($entry->getPathname());
    }
}
rmdir($temporary);
$testRoot = dirname($temporary);
if (is_dir($testRoot) && count(scandir($testRoot)) === 2) {
    rmdir($testRoot);
}

echo "Security regression tests passed.\n";
