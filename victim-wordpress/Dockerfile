ARG WP_TAG=6.6-php8.3-apache
FROM wordpress:${WP_TAG}

# Instrumented WordPress target: STOCK WordPress + PHP, plus packet capture and
# verbose PHP logging. No deliberately-vulnerable code, no planted include sink,
# no webshell. It is a realistic PHP app to fire the detection probe at and to
# observe session.upload_progress behaviour on a real stack.
RUN apt-get update && apt-get install -y --no-install-recommends \
      tcpdump procps \
    && rm -rf /var/lib/apt/lists/*

# LAB ONLY: session.upload_progress.cleanup = Off leaves the progress entry
# (incl. the attacker-controlled filename) on disk after the request completes,
# instead of PHP's stock "wipe it the instant the upload finishes" behaviour.
# This doesn't change what the vulnerability can do — the injected content
# exists either way — it just stops this harness from erasing the evidence
# before you can read it. Never set this in a production php.ini.
RUN mkdir -p /captures \
    && { \
      echo 'log_errors = On'; \
      echo 'error_log = /captures/wp_php_error.log'; \
      echo 'display_errors = Off'; \
      echo 'session.upload_progress.enabled = On'; \
      echo 'session.upload_progress.cleanup = Off'; \
    } > /usr/local/etc/php/conf.d/zz-lab-logging.ini

COPY wp-entrypoint.sh /usr/local/bin/wp-lab-entrypoint.sh
RUN chmod +x /usr/local/bin/wp-lab-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/wp-lab-entrypoint.sh"]
# hand off to the stock wordpress entrypoint + apache
CMD ["apache2-foreground"]
