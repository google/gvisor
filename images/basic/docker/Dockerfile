FROM docker:29.9.3-dind@sha256:08a98015fce594af7c382883bea080ea206de74402a95da9dc52b6428c8cd121

RUN apk add --no-cache bash iproute2 iptables

COPY start-dockerd.sh /start-dockerd.sh
ENTRYPOINT ["/start-dockerd.sh"]