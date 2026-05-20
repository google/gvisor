FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    libcap-dev \
    libmount-dev \
    git \
    rsync \
    vim \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src/linux
RUN git init && \
    git remote add origin https://github.com/torvalds/linux.git && \
    git sparse-checkout init --cone && \
    git sparse-checkout set \
        tools/testing/selftests \
        include/uapi \
        scripts \
        tools/include \
        tools/lib \
        tools/build \
        Makefile && \
    git fetch --depth 1 origin tag v6.8 && \
    git checkout FETCH_HEAD

WORKDIR /src/linux/tools/testing/selftests/pidfd

# TODO(b/290826530): Remove when CLONE_INTO_CGROUP is implemented in gVisor.
RUN sed -i '/PIDFD_NS_CGROUP,/d' pidfd_setns_test.c
RUN sed -i '/\[PIDFD_NS_CGROUP\]/d' pidfd_setns_test.c
RUN sed -i 's/| *CLONE_NEWCGROUP//g' pidfd_setns_test.c
RUN sed -i 's/CLONE_NEWCGROUP *|//g' pidfd_setns_test.c

# TODO(b/491161640): Remove when time namespaces are implemented in gVisor.
RUN sed -i '/PIDFD_NS_TIME,/d' pidfd_setns_test.c && \
    sed -i '/\[PIDFD_NS_TIME\]/d' pidfd_setns_test.c && \
    sed -i 's/| *CLONE_NEWTIME//g' pidfd_setns_test.c && \
    sed -i 's/CLONE_NEWTIME *|//g' pidfd_setns_test.c
# Neuter switch_timens() to just "return true;"
RUN sed -i '/static bool switch_timens(void)/,/^}/c static bool switch_timens(void) { return true; }' pidfd_setns_test.c

# TODO(b/491897692): Remove when CLONE_NEWUSER is implemented in gVisor's setns(), and
# b/491891436: when userns nsfs inodes are stable within a process.
RUN sed -i '/\[PIDFD_NS_USER\][[:space:]]*=[[:space:]]*{[[:space:]]*"user",[[:space:]]*CLONE_NEWUSER,[[:space:]]*},/d' pidfd_setns_test.c
RUN sed -i '/PIDFD_NS_USER,/d' pidfd_setns_test.c
# Strip CLONE_NEWUSER from setns().
RUN sed -i '/setns/ s/CLONE_NEWUSER[[:space:]]*|[[:space:]]*//g' pidfd_setns_test.c && \
    sed -i '/setns/ s/|[[:space:]]*CLONE_NEWUSER//g' pidfd_setns_test.c
# Drop the no_foul_play() test alltogether, for it needs setns() with CLONE_NEWUSER.
RUN sed -i '/TEST_F(current_nsset, no_foul_play)/,/^}/ s/^/\/\//' pidfd_setns_test.c

# Drop the test_pidfd_send_signal_recycled_pid_fail() test, for it takes long enough
# to occassionally breach bazel's 15min timeout for "large" tests.
# If seeking to run this test, comment the line below and uncomment the 
# PIDFD_MAX_DEFAULT-altering line that follows and also supply "-o 500" to the 
# run_kselftest.sh command at the end of this file.
RUN sed -i '/static int test_pidfd_send_signal_recycled_pid_fail(void)/,/^}/c static int test_pidfd_send_signal_recycled_pid_fail(void) { return 0; }' pidfd_test.c
# Increase PIDFD_MAX_DEFAULT to 65536 in test_pidfd_send_signal_recycled_pid_fail() in pidfd_test.c.
# The default value is smaller than the limit at which gVisor's pid allocator cycles back to 0.
# RUN sed -i 's/#define[[:space:]]*PIDFD_MAX_DEFAULT.*$/#define PIDFD_MAX_DEFAULT 0x10000/' pidfd_test.c

# Backup the modified source files for debugging before deleting /src/linux.
RUN mkdir -p /src/pidfd-tests
RUN cp -r /src/linux/tools/testing/selftests/pidfd /src/pidfd-tests

WORKDIR /src/linux/tools/testing/selftests
RUN make TARGETS=pidfd install INSTALL_PATH=/opt/kselftest

WORKDIR /opt/kselftest
# /dev/kmsg is not available in gvisor
RUN sed -i 's|\[ -w /dev/kmsg \] && echo "\(.*\)" >> /dev/kmsg|echo "\1"|' run_kselftest.sh

RUN rm -rf /src/linux

# exit 1 if "not ok" is seen.
CMD ["/bin/bash", "-c", "./run_kselftest.sh -c pidfd | tee /tmp/test.log; if grep -q 'not ok' /tmp/test.log; then echo 'FAILURE DETECTED'; exit 1; else exit 0; fi"]