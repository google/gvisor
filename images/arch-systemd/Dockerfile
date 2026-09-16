FROM archlinux@sha256:204e91950fd364961088a01773eee9012243b7e965fed42b1d82d12416190782

# Tell systemd it is running inside a container.
ENV container=docker

# Commit a machine-id at build time. Otherwise systemd-firstboot prompts on a
# console the container does not have, and systemd-machine-id-commit needs the
# nsfs ioctls gVisor lacks (gvisor.dev/issue/14757).
RUN systemd-machine-id-setup

# Mask services that do not work in gVisor (networkd/resolved: no
# NETLINK_PKTINFO, gvisor.dev/issue/13398; sysctl: unwritable /proc/sys) or
# make no sense in a container (udevd: host device events; getty@tty1: virtual
# terminals). Unlike Ubuntu, Arch presets enable networkd and resolved.
RUN ln -s /dev/null /etc/systemd/system/systemd-networkd.service && \
    ln -s /dev/null /etc/systemd/system/systemd-resolved.service && \
    ln -s /dev/null /etc/systemd/system/systemd-sysctl.service && \
    ln -s /dev/null /etc/systemd/system/systemd-udevd.service && \
    ln -s /dev/null /etc/systemd/system/getty@tty1.service

# Boot systemd as the container init process.
CMD ["/sbin/init"]
