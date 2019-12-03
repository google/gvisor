FROM ubuntu:18.04

RUN set -x \
        && apt-get update \
        && apt-get install -y \
            apache2 \
        && rm -rf /var/lib/apt/lists/*

# Link the htdoc directory to tmp.
RUN mkdir -p /usr/local/apache2/htdocs && \
        cd /usr/local/apache2 && ln -s /tmp htdocs

# Generate a bunch of relevant files.
RUN mkdir -p /local && \
        for size in 1 10 100 1000 1024 10240; do \
                dd if=/dev/zero of=/local/latin${size}k.txt count=${size} bs=1024; \
        done

# Standard settings.
ENV APACHE_RUN_DIR /tmp
ENV APACHE_RUN_USER nobody
ENV APACHE_RUN_GROUP nogroup
ENV APACHE_LOG_DIR /tmp
ENV APACHE_PID_FILE /tmp/apache.pid

# Copy on start-up; serve everything from /tmp (including the configuration).
CMD ["sh", "-c", "cp -a /local/* /tmp && apache2 -c \"ServerName localhost\" -c \"DocumentRoot /tmp\" -X"]
