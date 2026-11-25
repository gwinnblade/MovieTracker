FROM php:8.4-fpm AS runtime

RUN apt-get update && apt-get install -y \
    git \
    curl \
    libpng-dev \
    libonig-dev \
    libxml2-dev \
    libsqlite3-dev \
    sqlite3 \
    zip \
    unzip \
    nginx \
    supervisor \
    libicu-dev \
    libzip-dev \
    libfreetype6-dev \
    libjpeg62-turbo-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN docker-php-ext-configure gd --with-freetype --with-jpeg
RUN docker-php-ext-install pdo pdo_sqlite mbstring exif pcntl bcmath gd intl zip

RUN apt-get update && apt-get install -y libffi-dev \
    && docker-php-ext-install ffi \
    && printf 'ffi.enable=true\n' > /usr/local/etc/php/conf.d/ffi.ini \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

RUN sed -i 's/user = www-data/user = root/g' /usr/local/etc/php-fpm.d/www.conf && \
    sed -i 's/group = www-data/group = root/g' /usr/local/etc/php-fpm.d/www.conf

WORKDIR /var/www/backend

COPY composer.json composer.lock ./
RUN composer install --no-dev --optimize-autoloader --no-scripts

COPY . .

RUN mkdir -p bootstrap/cache storage/app/public storage/framework/cache/data \
    storage/framework/sessions storage/framework/views storage/logs

RUN rm -f /var/www/backend/public/storage

RUN composer install --no-dev --optimize-autoloader

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

RUN mkdir -p /var/www/backend/database /var/www/backend/storage \
    && chmod -R 777 /var/www/backend/database /var/www/backend/storage


RUN php artisan storage:link

EXPOSE 8000

CMD ["sh", "-c", "mkdir -p storage/app/public storage/framework/cache/data storage/framework/sessions storage/framework/views storage/logs && touch database/database.sqlite && php artisan migrate --force && php artisan app:bootstrap && supervisord -n"]

FROM runtime AS test
RUN composer install --no-interaction --prefer-dist
CMD ["php", "artisan", "test", "--compact"]
