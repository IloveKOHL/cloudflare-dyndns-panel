FROM php:8.2-apache

RUN apt-get update \
    && apt-get install -y --no-install-recommends cron \
    && rm -rf /var/lib/apt/lists/* \
    && printf '%s\n' 'expose_php=Off' 'display_errors=Off' 'log_errors=On' > /usr/local/etc/php/conf.d/security.ini

# Copy only runtime files to Apache web root
COPY --chown=root:root *.php .htaccess /var/www/html/
COPY --chown=root:root img /var/www/html/img
COPY --chown=root:root docker-entrypoint.sh /docker-entrypoint.sh
COPY docker/apache-security.conf /etc/apache2/conf-available/dyndns-security.conf
RUN a2enconf dyndns-security \
    && install -d -o www-data -g www-data -m 0700 /var/lib/cloudflare-dyndns-panel \
    && chmod 0755 /docker-entrypoint.sh

ENV DYNDNS_DATA_DIR=/var/lib/cloudflare-dyndns-panel
VOLUME ["/var/lib/cloudflare-dyndns-panel"]

# Expose port 80
EXPOSE 80

# Use the custom entrypoint script
CMD ["/docker-entrypoint.sh"]
