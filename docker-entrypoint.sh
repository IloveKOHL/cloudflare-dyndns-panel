#!/bin/bash
set -euo pipefail

data_dir="${DYNDNS_DATA_DIR:-/var/lib/cloudflare-dyndns-panel}"
install -d -o www-data -g www-data -m 0700 "$data_dir"
chown -R www-data:www-data "$data_dir"
chmod 0700 "$data_dir"

# Initialize credentials before Apache accepts connections. A random password is
# generated unless DYNDNS_INITIAL_PASSWORD (12+ characters) was supplied.
runuser -u www-data -- php -r "require '/var/www/html/bootstrap.php'; loadConfig();"
if [ -f "$data_dir/initial_password.txt" ] && mkdir -m 0700 "$data_dir/.initial_password_announced" 2>/dev/null; then
  echo "Generated initial panel password (change it after login):"
  sed -n '1p' "$data_dir/initial_password.txt"
fi

# Start cron
service cron start

# Start Apache in foreground
apache2-foreground
