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
RUN { \
      echo 'log_errors = On'; \
      echo 'error_log = /captures/php_error.log'; \
      echo 'display_errors = Off'; \
    } > /usr/local/etc/php/conf.d/zz-lab-logging.ini

COPY entrypoint.sh /usr/local/bin/lab-entrypoint.sh
RUN chmod +x /usr/local/bin/lab-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/lab-entrypoint.sh"]
CMD ["apache2-foreground"]
