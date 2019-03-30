FROM node:10.15.1-stretch-slim

LABEL MAINTAINER="ianlewis@google.com"

ARG HUGO_VERSION
ENV HUGO_DOWNLOAD_URL=https://github.com/spf13/hugo/releases/download/v${HUGO_VERSION}/hugo_extended_${HUGO_VERSION}_Linux-64bit.tar.gz

RUN set -x \
        && apt-get update \
        && apt-get install -y \
            ca-certificates \
            git \
            make \
        && rm -rf /var/lib/apt/lists/*

RUN wget "$HUGO_DOWNLOAD_URL" && \
	tar xzf hugo_extended_${HUGO_VERSION}_Linux-64bit.tar.gz && \
	mv hugo /usr/bin/hugo && \
	rm hugo_extended_${HUGO_VERSION}_Linux-64bit.tar.gz LICENSE README.md

CMD ["hugo"]
