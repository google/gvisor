FROM ruby:3.0-alpine

# Some of these dependencies are called as subprocesses by the fastlane tests.
RUN apk add --no-cache ruby ruby-dev ruby-bundler ruby-json build-base bash \
    wget git unzip
RUN wget -q \
      'https://github.com/fastlane/fastlane/archive/refs/tags/2.207.0.tar.gz' \
      -O /tmp/fastlane.tar.gz \
    && mkdir /fastlane \
    && cd /fastlane \
    && tar xfz /tmp/fastlane.tar.gz --strip-components=1 \
    && rm /tmp/fastlane.tar.gz \
    && for i in 1 2 3; do if bundle install; then break; fi; done
COPY . /files/
