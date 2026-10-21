ARG PHP_TAG=8.3-apache
FROM php:${PHP_TAG}

# Instrumented target. This is a STOCK PHP image plus packet capture — it contains
# no deliberately-vulnerable or exploit code. To reproduce a specific affected build,
# set PHP_TAG in .env to that version once php.net publishes the affected range.
RUN apt-get update && apt-get install -y --no-install-recommends \
      tcpdump procps \
    && rm -rf /var/lib/apt/lists/*

# Minimal landing page so the server responds; no app logic.
RUN printf '<?php phpinfo(INFO_GENERAL); ' > /var/www/html/index.php \
    && mkdir -p /captures

# Verbose logging to help detection engineering.
#
# LAB ONLY: session.upload_progress.cleanup = Off leaves the progress entry
# (incl. the attacker-controlled filename) on disk after the request completes,
# instead of PHP's stock "wipe it the instant the upload finishes" behaviour.
# This doesn't change what the vulnerability can do — the injected content
# exists either way — it just stops this harness from erasing the evidence
# before you can read it. Never set this in a production php.ini.
RUN { \
      echo 'log_errors = On'; \
      echo 'error_log = /captures/php_error.log'; \
      echo 'display_errors = Off'; \
      echo 'session.upload_progress.enabled = On'; \
      echo 'session.upload_progress.cleanup = Off'; \
    } > /usr/local/etc/php/conf.d/zz-lab-logging.ini

COPY entrypoint.sh /usr/local/bin/lab-entrypoint.sh
RUN chmod +x /usr/local/bin/lab-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/lab-entrypoint.sh"]
CMD ["apache2-foreground"]
