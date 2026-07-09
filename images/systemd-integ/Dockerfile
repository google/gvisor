FROM ubuntu:26.04

# Tell systemd it is running inside a container.
ENV container=docker

# Install systemd and some utils.
RUN apt-get update && \
    apt-get install -y systemd systemd-sysv dbus dbus-user-session libpam-systemd sudo vim jq && \
    apt-get clean

# Mask services that don't work in gVisor.
RUN ln -s /dev/null /etc/systemd/system/systemd-sysctl.service
RUN ln -s /dev/null /etc/systemd/system/e2scrub_reap.service
RUN ln -s /dev/null /etc/systemd/system/getty@tty1.service
RUN ln -s /dev/null /etc/systemd/system/systemd-resolved.service
RUN ln -s /dev/null /etc/systemd/system/tmp.mount

# Write a test daemon script.
RUN printf '#!/bin/bash\nwhile true; do\n    echo "Hello from test daemon at $(date)"\n    sleep 5\ndone\n' > /usr/local/bin/test-daemon.sh && \
    chmod +x /usr/local/bin/test-daemon.sh

# Write the systemd unit file for the test daemon.
RUN printf '[Unit]\nDescription=Test Daemon\n\n[Service]\nExecStart=/usr/local/bin/test-daemon.sh\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=default.target\n' > /etc/systemd/system/test-daemon.service

# Boot systemd as the container init process.
CMD ["/sbin/init"]