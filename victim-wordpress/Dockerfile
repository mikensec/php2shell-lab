ARG WP_TAG=6.6-php8.3-apache
FROM wordpress:${WP_TAG}

# Instrumented WordPress target: STOCK WordPress + PHP, plus packet capture and
# verbose PHP logging. No deliberately-vulnerable code, no planted include sink,
# no webshell. It is a realistic PHP app to fire the detection probe at and to
# observe session.upload_progress behaviour on a real stack.
RUN apt-get update && apt-get install -y --no-install-recommends \
      tcpdump procps \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /captures \
    && { \
      echo 'log_errors = On'; \
      echo 'error_log = /captures/wp_php_error.log'; \
      echo 'display_errors = Off'; \
      # leave session.upload_progress at stock defaults; override only in the lab
      echo '; session.upload_progress.cleanup = On  (stock; do not relax in prod)'; \
    } > /usr/local/etc/php/conf.d/zz-lab-logging.ini

COPY wp-entrypoint.sh /usr/local/bin/wp-lab-entrypoint.sh
RUN chmod +x /usr/local/bin/wp-lab-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/wp-lab-entrypoint.sh"]
# hand off to the stock wordpress entrypoint + apache
CMD ["apache2-foreground"]
