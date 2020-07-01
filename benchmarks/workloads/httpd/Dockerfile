FROM ubuntu:18.04

RUN set -x \
        && apt-get update \
        && apt-get install -y \
            apache2 \
        && rm -rf /var/lib/apt/lists/*

# Generate a bunch of relevant files.
RUN mkdir -p /local && \
        for size in 1 10 100 1000 1024 10240; do \
                dd if=/dev/zero of=/local/latin${size}k.txt count=${size} bs=1024; \
        done

# Rewrite DocumentRoot to point to /tmp/html instead of the default path.
RUN sed -i 's/DocumentRoot.*\/var\/www\/html$/DocumentRoot   \/tmp\/html/' /etc/apache2/sites-enabled/000-default.conf
COPY ./apache2-tmpdir.conf /etc/apache2/sites-enabled/apache2-tmpdir.conf

# Standard settings.
ENV APACHE_RUN_DIR /tmp
ENV APACHE_RUN_USER nobody
ENV APACHE_RUN_GROUP nogroup
ENV APACHE_LOG_DIR /tmp
ENV APACHE_PID_FILE /tmp/apache.pid

# Copy on start-up; serve everything from /tmp (including the configuration).
CMD ["sh", "-c", "mkdir -p /tmp/html && cp -a /local/* /tmp/html && apache2 -X"]
