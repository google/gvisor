FROM alpine

RUN apk add libcap

RUN cp  /bin/busybox /mnt/cat && setcap cap_net_admin+ep /mnt/cat
