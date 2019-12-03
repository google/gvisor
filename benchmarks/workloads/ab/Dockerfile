FROM ubuntu:18.04

RUN set -x \
        && apt-get update \
        && apt-get install -y \
            apache2-utils \
        && rm -rf /var/lib/apt/lists/*

# Parameterized workload.
ENV requests 5000
ENV connections 10
ENV host localhost
ENV port 8080
ENV path notfound
CMD ["sh", "-c", "ab -n ${requests} -c ${connections} http://${host}:${port}/${path}"]
