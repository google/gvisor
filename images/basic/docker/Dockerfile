FROM docker:dind

RUN apk add --no-cache bash iproute2 iptables

COPY start-dockerd.sh /start-dockerd.sh
ENTRYPOINT ["/start-dockerd.sh"]