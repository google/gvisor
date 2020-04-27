FROM ubuntu:18.04

RUN set -x \
        && apt-get update \
        && apt-get install -y \
            iperf \
        && rm -rf /var/lib/apt/lists/*

# Accept a host parameter.
ENV host ""
ENV port 5001

# Start as client if the host is provided.
CMD ["sh", "-c", "test -z \"${host}\" && iperf -s || iperf -f K --realtime -c ${host} -p ${port}"]
