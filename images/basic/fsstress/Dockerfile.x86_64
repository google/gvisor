# Usage: docker run --rm fsstress -d /test -n 10000 -p 100 -X -v
FROM alpine

RUN apk update && apk add git
RUN git clone https://github.com/linux-test-project/ltp.git --depth 1

WORKDIR /ltp
RUN ./travis/alpine.sh
RUN make autotools && ./configure
RUN make -C testcases/kernel/fs/fsstress
RUN cp ./testcases/kernel/fs/fsstress/fsstress /usr/bin
RUN rm -rf /fsstress /tmp

WORKDIR /
# This is required, otherwise running with -p > 1 prematurelly exits.
COPY run.sh .
ENTRYPOINT ["/run.sh"]
