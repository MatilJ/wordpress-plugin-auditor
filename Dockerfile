FROM wordpress:php8.3-apache

# Install system dependencies + libraries for PHP extensions
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        curl \
        git \
        less \
        unzip \
        libzip-dev \
        zip \
        libicu-dev \
        libxml2-dev \
        libfreetype6-dev \
        libjpeg62-turbo-dev \
        libpng-dev \
        libwebp-dev \
        libonig-dev \
    ; \
    rm -rf /var/lib/apt/lists/*

# Install PHP extensions commonly required by WordPress plugins.
# pdo_mysql:  Illuminate/Database (Laravel DB), many analytics/form plugins
# gd:        image manipulation (favicons, thumbnails, captchas)
# intl:      i18n, number/date formatting, Symfony validators
# soap:      payment gateways, shipping APIs
# exif:      media library plugins
# mbstring:  already in base image but ensure it's present
RUN set -eux; \
    docker-php-ext-configure gd --with-freetype --with-jpeg --with-webp; \
    docker-php-ext-configure zip; \
    docker-php-ext-configure intl; \
    docker-php-ext-install -j$(nproc) \
        zip \
        pdo_mysql \
        gd \
        intl \
        soap \
        exif

# Install Xdebug
RUN pecl install xdebug \
    && docker-php-ext-enable xdebug

# Configure Xdebug
COPY xdebug.ini /usr/local/etc/php/conf.d/xdebug.ini

# Install WP-CLI
RUN curl -o /usr/local/bin/wp https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
    && chmod +x /usr/local/bin/wp

# Optional: Modify PHP configuration
RUN mv "$PHP_INI_DIR/php.ini-development" "$PHP_INI_DIR/php.ini"

# Wrapper named "apache2-*" so docker-entrypoint.sh still triggers its WordPress
# setup path (it checks `$1 == apache2*`), then fixes wp-content/uploads ownership
# before handing off to the real Apache process.
RUN printf '#!/bin/bash\nmkdir -p /var/www/html/wp-content/uploads\nchown -R www-data:www-data /var/www/html/wp-content/uploads\nexec apache2-foreground "$@"\n' \
    > /usr/local/bin/apache2-with-perms-fix \
    && chmod +x /usr/local/bin/apache2-with-perms-fix