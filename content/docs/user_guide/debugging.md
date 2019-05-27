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

> Note: the last `/` in `--debug-log` is needed to interpret it as a directory.
> Then each `runsc` command executed will create a separate log file.
> Otherwise, log messages from all commands will be appended to the same file.

You may also want to pass `--log-packets` to troubleshoot network problems. Then
restart the Docker daemon:

```bash
sudo systemctl restart docker
```

Run your container again, and inspect the files under `/tmp/runsc`. The log file
ending with `.boot` will contain the strace logs from your application, which can
be useful for identifying missing or broken system calls in gVisor. If you are
having problems starting the container, the log file ending with `.create` may
have the reason for the failure.

## Stack traces

The command `runsc debug --stacks` collects stack traces while the sandbox is
running which can be useful to troubleshoot issues or just to learn more about
gVisor. It connects to the sandbox process, collects a stack dump, and writes
it to the console. For example:

```bash
docker run --runtime=runsc --rm -d alpine sh -c "while true; do echo running; sleep .1; done"
63254c6ab3a6989623fa1fb53616951eed31ac605a2637bb9ddba5d8d404b35b

sudo runsc --root /var/run/docker/runtime-runsc/moby debug --stacks 63254c6ab3a6989623fa1fb53616951eed31ac605a2637bb9ddba5d8d404b35b
```

> Note: `--root` variable is provided by docker and is normally set to
> `/var/run/docker/runtime-[runtime-name]/moby`. If in doubt, `--root` is logged to
> `runsc` logs.

## Profiling

`runsc` integrates with Go profiling tools and gives you easy commands to profile
CPU and heap usage. First you need to enable `--profile` in the command line options
before starting the container:

```json
{
    "runtimes": {
        "runsc-prof": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--profile"
            ]
       }
    }
}
```

> Note: Enabling profiling loosens the seccomp protection added to the sandbox,
> and should not be run in production under normal circumstances.

Then restart docker to refresh the runtime options. While the container is running,
execute `runsc debug` to collect profile information and save to a file. Here are
the options available:

 * **--profile-heap:** Generates heap profile to the speficied file.
 * **--profile-cpu:** Enables CPU profiler, waits for `--profile-delay` seconds 
   and generates CPU profile to the speficied file.

For example:

```bash
docker run --runtime=runsc-prof --rm -d alpine sh -c "while true; do echo running; sleep .1; done"
63254c6ab3a6989623fa1fb53616951eed31ac605a2637bb9ddba5d8d404b35b

sudo runsc --root /var/run/docker/runtime-runsc-prof/moby debug --profile-heap=/tmp/heap.prof 63254c6ab3a6989623fa1fb53616951eed31ac605a2637bb9ddba5d8d404b35b
sudo runsc --root /var/run/docker/runtime-runsc-prof/moby debug --profile-cpu=/tmp/cpu.prof --profile-delay=30 63254c6ab3a6989623fa1fb53616951eed31ac605a2637bb9ddba5d8d404b35b
```

The resulting files can be opened using `go tool pprof` or [pprof]. The examples 
below create image file (`.svg`) with the heap profile and writes the top 
functions using CPU to the console:

```bash
go tool pprof -svg /usr/local/bin/runsc /tmp/heap.prof
go tool pprof -top /usr/local/bin/runsc /tmp/cpu.prof
```

[pprof]: https://github.com/google/pprof/blob/master/doc/README.md
