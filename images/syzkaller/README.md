syzkaller is an unsupervised coverage-guided kernel fuzzer.

*   [Github](https://github.com/google/syzkaller)
*   [gVisor dashboard](https://syzkaller.appspot.com/gvisor)

# How to run syzkaller.

First, we need to load a syzkaller docker image:

```bash
make load-syzkaller
```

or we can rebuild it to use an up-to-date version of the master branch:

```bash
make rebuild-syzkaller
```

Then we need to create a directory with all artifacts that we will need to run a
syzkaller. Then we will bind-mount this directory to a docker container.

We need to build runsc and place it on the artifact directory:

```bash
make RUNTIME_DIR=/tmp/syzkaller refresh
```

The next step is to create a syzkaller config. We can copy the default one and
customize it:

```bash
cp images/syzkaller/default-gvisor-config.cfg /tmp/syzkaller/syzkaller.cfg
```

Now we can start syzkaller in a docker container:

```bash
docker run --privileged -it --rm \
    -v /tmp/syzkaller:/tmp/syzkaller \
    gvisor.dev/images/syzkaller:latest
```

All logs will be in /tmp/syzkaller/workdir.

# How to run a syz repro.

We need to repeat all preparation steps from the previous section and save a
syzkaller repro in /tmp/syzkaller/repro.

Now we can run syz-repro to reproduce a crash:

```bash
docker run --privileged -it --rm -v
    /tmp/syzkaller:/tmp/syzkaller --entrypoint=""
    gvisor.dev/images/syzkaller:latest ./bin/syz-repro -config
    /tmp/syzkaller/syzkaller.cfg /tmp/syzkaller/repro
```
