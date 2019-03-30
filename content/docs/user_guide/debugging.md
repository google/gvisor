+++
title = "Debugging"
weight = 120
+++

To enable debug and system call logging, add the `runtimeArgs` below to your
[Docker](../docker/) configuration (`/etc/docker/daemon.json`):

```json
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--debug-log=/tmp/runsc/",
                "--debug",
                "--strace"
            ]
       }
    }
}
```

You may also want to pass `--log-packets` to troubleshoot network problems. Then
restart the Docker daemon:

```bash
sudo systemctl restart docker
```

Run your container again, and inspect the files under `/tmp/runsc`. The log file
with name `boot` will contain the strace logs from your application, which can
be useful for identifying missing or broken system calls in gVisor.
