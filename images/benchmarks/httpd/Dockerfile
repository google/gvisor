FROM ubuntu:18.04

RUN set -x \
        && apt-get update \
        && apt-get install -y \
            apache2 \
        && rm -rf /var/lib/apt/lists/*

# Generate a bunch of relevant files.
RUN mkdir -p /local && \
        for size in 1 10 100 1024 10240; do \
                dd if=/dev/zero of=/local/latin${size}k.txt count=${size} bs=1024; \
        done

# Rewrite DocumentRoot to point to /tmp/html instead of the default path.
RUN sed -i 's/DocumentRoot.*\/var\/www\/html$/DocumentRoot   \/tmp\/html/' /etc/apache2/sites-enabled/000-default.conf
COPY ./apache2-tmpdir.conf /etc/apache2/sites-enabled/apache2-tmpdir.conf
