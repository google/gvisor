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

# Standard settings.
ENV APACHE_RUN_DIR /disk
ENV APACHE_RUN_USER nobody
ENV APACHE_RUN_GROUP nogroup
ENV APACHE_LOG_DIR /disk
ENV APACHE_PID_FILE /disk/apache.pid

# Copy on start-up; serve everything from /tmp (including the configuration).
CMD ["sh", "-c", "mkdir -p /disk/htdocs && cp -a /local/* /disk/htdocs && apache2 -c \"ServerName localhost\" -c \"DocumentRoot /disk/htdocs\" -X"]
