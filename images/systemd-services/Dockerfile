FROM ubuntu:26.04@sha256:b7f48194d4d8b763a478a621cdc81c27be222ba2206ca3ca6bc42b49685f3d9e

# Tell systemd it is running inside a container.
ENV container=docker
ENV DEBIAN_FRONTEND=noninteractive

# Install systemd and popular software that runs as systemd services.
RUN apt-get update && \
    apt-get install -y \
    systemd systemd-sysv dbus dbus-user-session libpam-systemd sudo curl \
    openssh-server openssh-client \
    nginx \
    apache2 \
    postgresql \
    mariadb-server \
    redis-server \
    docker.io && \
    apt-get clean

# Mask services that will not work in gVisor.
RUN ln -s /dev/null /etc/systemd/system/systemd-sysctl.service && \
    ln -s /dev/null /etc/systemd/system/e2scrub_reap.service && \
    ln -s /dev/null /etc/systemd/system/getty@tty1.service && \
    ln -s /dev/null /etc/systemd/system/systemd-resolved.service

# Do not start any of the service packages at boot: each test starts only the
# service it exercises. Ubuntu auto-enables services on package install.
RUN systemctl disable \
    ssh ssh.socket nginx apache2 postgresql mariadb redis-server \
    docker docker.socket containerd

# For dockerd's benefit.
RUN mkdir -p /etc/docker && \
    printf '{"iptables": false, "ip6tables": false, "debug": true}\n' > /etc/docker/daemon.json

# Boot systemd as the container init process.
CMD ["/sbin/init"]
