FROM nginx:1.15.10

# Generate a bunch of relevant files.
RUN mkdir -p /local && \
        for size in 1 10 100 1024 10240; do \
                dd if=/dev/zero of=/local/latin${size}k.txt count=${size} bs=1024; \
        done

RUN touch /local/index.html

COPY ./nginx.conf /etc/nginx/nginx.conf
COPY ./nginx_gofer.conf /etc/nginx/nginx_gofer.conf
