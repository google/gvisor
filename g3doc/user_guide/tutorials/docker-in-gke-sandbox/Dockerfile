FROM ubuntu:22.04

ENV DEBIAN_FRONTEND="noninteractive"
RUN apt-get update && apt-get install -y docker.io

COPY docker-run.sh /usr/local/bin/docker-run.sh

CMD /usr/local/bin/docker-run.sh
