FROM ubuntu:26.04

# Tell systemd it is running inside a container.
ENV container=docker
ENV DEBIAN_FRONTEND=noninteractive

# Install systemd and popular software that runs as systemd services.
RUN apt-get update && \
    apt-get install -y \
    systemd systemd-sysv dbus dbus-user-session libpam-systemd sudo curl && \
    apt-get clean

# Mask services that will not work in gVisor.
RUN ln -s /dev/null /etc/systemd/system/systemd-sysctl.service && \
    ln -s /dev/null /etc/systemd/system/e2scrub_reap.service && \
    ln -s /dev/null /etc/systemd/system/getty@tty1.service && \
    ln -s /dev/null /etc/systemd/system/systemd-resolved.service

# Boot systemd as the container init process.
CMD ["/sbin/init"]
