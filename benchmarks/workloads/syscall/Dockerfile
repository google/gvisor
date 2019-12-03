FROM gcc:latest
COPY . /usr/src/syscall
WORKDIR /usr/src/syscall
RUN gcc -O2 -o syscall syscall.c
ENV count 1000000
CMD ["sh", "-c", "./syscall ${count}"]
