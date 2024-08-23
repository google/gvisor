FROM ubuntu:jammy

RUN set -x \
        && apt-get update \
        && apt-get install -y \
            ffmpeg \
        && rm -rf /var/lib/apt/lists/*
WORKDIR /media
ADD https://samples.ffmpeg.org/MPEG-4/video.mp4 video.mp4
