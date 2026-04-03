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

WORKDIR /src
RUN git clone --depth 1 --branch v6.8 https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git

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

# Increase PIDFD_MAX_DEFAULT to 65536 in test_pidfd_send_signal_recycled_pid_fail() in pidfd_test.c.
# The default value is smaller than the limit at which gVisor's pid allocator cycles back to 0.
RUN sed -i 's/#define[[:space:]]*PIDFD_MAX_DEFAULT.*$/#define PIDFD_MAX_DEFAULT 0x10000/' pidfd_test.c

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
# Note: the "-o 500" is necessary for test_pidfd_send_signal_recycled_pid_fail() from pidfd_test.c to complete.
# Note: Supply "-t pidfd:pidfd_test" to run a single test.
CMD ["/bin/bash", "-c", "./run_kselftest.sh -c pidfd -o 500 | tee /tmp/test.log; if grep -q 'not ok' /tmp/test.log; then echo 'FAILURE DETECTED'; exit 1; else exit 0; fi"]