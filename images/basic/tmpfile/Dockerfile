# Create file under /tmp to ensure files inside '/tmp' are not overridden.
FROM alpine:3.11.5
RUN mkdir -p /tmp/foo \
  && echo 123 > /tmp/foo/file.txt
