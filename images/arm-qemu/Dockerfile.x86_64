FROM fedora:33

RUN dnf install -y qemu-system-aarch64 gzip cpio wget

WORKDIR /workdir
RUN wget -4 http://dl-cdn.alpinelinux.org/alpine/edge/releases/aarch64/netboot/vmlinuz-lts
RUN wget -4 http://dl-cdn.alpinelinux.org/alpine/edge/releases/aarch64/netboot/initramfs-lts

COPY initramfs /workdir/initramfs
COPY test.sh /workdir/

CMD ./test.sh
