FROM ubuntu:22.04

ENV DEBIAN_FRONTEND="noninteractive"
RUN apt-get update && apt-get install -y docker.io

COPY start-dockerd.sh .
CMD /start-dockerd.sh