FROM ubuntu:jammy

RUN set -x \
        && apt-get update \
        && apt-get install -y \
            ffmpeg \
        && rm -rf /var/lib/apt/lists/*
WORKDIR /media
ADD https://samples.ffmpeg.org/MPEG-4/video.mp4 video.mp4
ADD https://samples.ffmpeg.org/A-codecs/Nelly_Moser/h264_NellyMoser.mp4 encoded.mp4
ENV PATH=$PATH:/usr/local/nvidia/bin
