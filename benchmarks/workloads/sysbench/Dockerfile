FROM ubuntu:18.04

RUN set -x \
        && apt-get update \
        && apt-get install -y \
            sysbench \
        && rm -rf /var/lib/apt/lists/*

# Parameterize the tests.
ENV test cpu
ENV threads 1
ENV options ""

# run sysbench once as a warm-up and take the second result
CMD ["sh", "-c", "sysbench --threads=8 --memory-total-size=5G memory run > /dev/null && \
sysbench --threads=${threads} ${options} ${test} run"]
