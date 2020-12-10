# Go is easy, since we already have everything we need to compile the proctor
# binary and run the tests in the golang Docker image.
FROM golang:1.12
RUN ["go", "tool", "dist", "test", "-compile-only"]
