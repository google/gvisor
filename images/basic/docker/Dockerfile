FROM ubuntu:24.04

ENV DEBIAN_FRONTEND="noninteractive"
RUN apt-get update && apt-get -y install ca-certificates curl
# TODO(gvisor.dev/issue/11883): use the latest docker version.
RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc && \
  chmod a+r /etc/apt/keyrings/docker.asc && \
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list && \
  apt-get update && \
  apt-get install -qqy docker-ce=5:27.5.1-1~ubuntu.24.04~noble docker-ce-cli=5:27.5.1-1~ubuntu.24.04~noble containerd.io docker-buildx-plugin docker-compose-plugin iproute2

COPY start-dockerd.sh .
CMD /start-dockerd.sh
