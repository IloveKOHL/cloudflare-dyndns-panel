#!/bin/bash

# Check Root
if [ "$EUID" -ne 0 ]; then
  echo "Bitte als root ausführen."
  exit 1
fi

RAM=512
CPU=1
BRIDGE="vmbr0"

read -r -p "CT-ID (z.B. 100): " CTID
read -r -p "Hostname für CT (z.B. ubuntu-web): " CT_HOSTNAME


if ! [[ "$CTID" =~ ^[0-9]+$ ]] || ! [[ "$CT_HOSTNAME" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,61}[a-zA-Z0-9])?$ ]]; then
  echo "CT-ID und Hostname sind erforderlich."
  exit 1
fi

while true; do
  read -r -s -p "Sicheres Root-Passwort für den CT (mindestens 12 Zeichen): " CT_ROOT_PASSWORD
  echo
  read -r -s -p "Root-Passwort wiederholen: " CT_ROOT_PASSWORD_CONFIRM
  echo
  if [ "${#CT_ROOT_PASSWORD}" -lt 12 ]; then
    echo "Das Passwort muss mindestens 12 Zeichen lang sein."
  elif [ "$CT_ROOT_PASSWORD" != "$CT_ROOT_PASSWORD_CONFIRM" ]; then
    echo "Die Passwörter stimmen nicht überein."
  else
    break
  fi
done
unset CT_ROOT_PASSWORD_CONFIRM

echo "CT wird erstellt..."

pct create "$CTID" local:vztmpl/ubuntu-22.04-standard_22.04-1_amd64.tar.zst \
  -hostname "$CT_HOSTNAME" \
  -memory $RAM \
  -cores $CPU \
  -net0 name=eth0,bridge=$BRIDGE,ip=dhcp \
  -rootfs local-lvm:8 \
  -start 0

echo "CT $CTID erstellt. Starte CT..."

pct start "$CTID"

echo "Warte 10 Sekunden, bis CT bootet..."
sleep 10

echo "Setup im CT wird ausgeführt..."

printf '%s\n' "$CT_ROOT_PASSWORD" | pct exec "$CTID" -- bash -c '
  IFS= read -r root_password
  printf "root:%s\n" "$root_password" | chpasswd
  unset root_password

  if [ "$(lsb_release -is 2>/dev/null)" != "Ubuntu" ]; then
    echo "Nicht Ubuntu, Setup kann abweichen."
  else
    echo "Ubuntu erkannt."
  fi

  # Pakete prüfen & installieren falls nicht vorhanden
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends apache2 php php-curl php-json php-cli git cron

  systemctl enable apache2 cron
  systemctl start apache2 cron

  cd /var/www/html

  if [ ! -d cloudflare-dyndns-panel ]; then
    git clone https://github.com/IloveKOHL/cloudflare-dyndns-panel.git
  fi

  cp -a cloudflare-dyndns-panel/. .
  rm -rf /var/www/html/cloudflare-dyndns-panel
  rm -rf /var/www/html/.git

  install -d -o www-data -g www-data -m 0700 /var/lib/cloudflare-dyndns-panel
  cp /var/www/html/docker/apache-security.conf /etc/apache2/conf-available/dyndns-security.conf
  a2enconf dyndns-security
  chown -R root:root /var/www/html
  find /var/www/html -type d -exec chmod 0755 {} +
  find /var/www/html -type f -exec chmod 0644 {} +
  systemctl reload apache2

  # Standard Apache index.html löschen
  rm -f /var/www/html/index.html
'
unset CT_ROOT_PASSWORD

echo "Setup abgeschlossen!"
echo "CT $CTID läuft mit Ubuntu Webserver & DynDNS Panel."
