FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    git \
    python3 \
    make

WORKDIR /testsuite
RUN git clone https://github.com/amir73il/unionmount-testsuite.git .

# This procfs node does not exist inside gvisor.
RUN sed -i 's/read_file("\/proc\/sys\/kernel\/tainted")/ "0"/' tool_box.py
# For verbose mode "-v" to work inside gvisor.
RUN sed -i 's/write_file("\/dev\/kmsg", data)/print(data)/' tool_box.py
# b/486230184: gvisor does not support `redirect_dir`.
RUN : > tests/rename-exdev.py