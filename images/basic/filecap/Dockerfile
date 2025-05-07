FROM alpine

RUN apk add libcap

RUN cp /bin/cat /mnt/cat && setcap cap_net_admin+ep /mnt/cat
