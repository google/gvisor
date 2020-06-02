# Go is easy, since we already have everything we need to compile the proctor
# binary and run the tests in the golang Docker image.
FROM golang:1.12
# This step will take a lot of time in a cross-compilation environment.
# Skip this one for now.
RUN if [ $(uname -m) = "x86_64" ]; then \
       go tool dist test -compile-only; \
    fi
