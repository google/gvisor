FROM ubuntu:24.04

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y strace sudo util-linux libcap2-bin

RUN groupadd container_admins
RUN useradd -m alice -G container_admins
RUN useradd -m bob
RUN echo '%container_admins ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER alice