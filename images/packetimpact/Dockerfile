FROM ubuntu:bionic
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        # iptables to disable OS native packet processing.
        iptables \
        # nc to check that the posix_server is running.
        netcat \
        # tcpdump to log brief packet sniffing.
        tcpdump \
        # ip link show to display MAC addresses.
        iproute2 \
        # tshark to log verbose packet sniffing.
        tshark \
        # killall for cleanup.
        psmisc
RUN hash -r
CMD /bin/bash
