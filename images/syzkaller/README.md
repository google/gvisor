syzkaller is an unsupervised coverage-guided kernel fuzzer.

*   [Github](https://github.com/google/syzkaller)
*   [gVisor dashboard](https://syzkaller.appspot.com/gvisor)

# How to run syzkaller.

*   Build the syzkaller docker image `make load-syzkaller`
*   Build runsc and place it in /tmp/syzkaller. `make RUNTIME_DIR=/tmp/syzkaller
    refresh`
*   Copy the syzkaller config in /tmp/syzkaller `cp
    images/syzkaller/default-gvisor-config.cfg /tmp/syzkaller/syzkaller.cfg`
*   Run syzkaller `docker run --privileged -it --rm -v
    /tmp/syzkaller:/tmp/syzkaller gvisor.dev/images/syzkaller:latest`

# How to run a syz repro.

*   Repeate all steps except the last one from the previous section.

*   Save a syzkaller repro in /tmp/syzkaller/repro

*   Run syz-repro `docker run --privileged -it --rm -v
    /tmp/syzkaller:/tmp/syzkaller --entrypoint=""
    gvisor.dev/images/syzkaller:latest ./bin/syz-repro -config
    /tmp/syzkaller/syzkaller.cfg /tmp/syzkaller/repro`
