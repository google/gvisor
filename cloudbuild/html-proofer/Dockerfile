FROM ruby:2.4-alpine

LABEL MAINTAINER="ianlewis@google.com"

ARG HTMLPROOFER_VERSION

RUN set -x \
        && apk add --no-cache \
            build-base \
            ca-certificates \
            curl \
            wget \
            libcurl \
            libxml2-dev \
            libxslt-dev \
            openssh
        && gem install \
            html-proofer:${HTMLPROOFER_VERSION} \
            nokogiri:1.10.1 \
        --no-document

CMD ["htmlproofer"]

