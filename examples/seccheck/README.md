# gVisor Seccheck Examples

## C++ Server

This directory provides an example of a monitoring process that receives
connections from gVisor sandboxes and prints the traces to `stdout`. The example
contains two main files:

*   **server.cc**: this is where `main()` and all the code is. It sets up a
    server listening to a Unix-domain socket located at
    `/tmp/gvisor_events.sock` or a configurable location via a command line
    argument.
*   **pod_init.json**: this file contains the trace configuration that should be
    passed to `runsc`. It can be done either via `--pod-init-config` flag or
    using `runsc trace create` command. Note that the socket location is
    specified in this file, in case you change it.

### Usage

First start the server in a terminal, which will block and wait for new
connections:

```shell
$ bazel run examples/seccheck:server_cc
Socket address /tmp/gvisor_events.sock
```

Now, open a **second, separate terminal** to trigger a simple example using
`runsc do`. We recommend building and executing `runsc` directly from the source
tree via Bazel to ensure it contains the latest trace points configuration
needed for this example, rather than accidentally using an older system-provided
binary:

```shell
$ bazel run runsc -- \
    --rootless --network=none \
    --pod-init-config=$PWD/examples/seccheck/pod_init.json \
    do echo 123
```

Back at the server terminal, you can see the following traces being output:

```
Connection accepted
Start => id:     "runsc-329739" cwd: "/home/fvoznika" args: "echo" args: "123"
E Open sysno:    257 fd: -100 pathname: "/usr/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3/libc.so.6" flags: 524288
X Open exit      { errorno: 2 } sysno: 257 fd: -100 pathname: "/usr/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3/libc.so.6" flags: 524288
E Open sysno:    257 fd: -100 pathname: "/usr/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v2/libc.so.6" flags: 524288
X Open exit      { errorno: 2 } sysno: 257 fd: -100 pathname: "/usr/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v2/libc.so.6" flags: 524288
...
TaskExit =>
Connection closed
```

Connection messages indicate when `runsc` connected to and disconnected from the
server. Then there is a trace for container start and a few syscalls to
`open(2)` for searching libraries. You can change `pod_init.json` to configure
the trace session to your liking.

To set this up with Docker, you can add the `--pod-init-config` flag when the
runtime is installed:

```shell
# Rebuild runsc and copy to a stable location
$ mkdir -p bin
$ make copy TARGETS=//:release DESTINATION=bin/
$ sudo cp -r --preserve=mode bin/runsc bin/containerd-shim-runsc-v1 bin/gvisor-bin /usr/local/bin/
$ sudo /usr/local/bin/runsc install --runtime=runsc-trace -- \
    --pod-init-config=$PWD/examples/seccheck/pod_init.json

# Restart the Docker daemon so it reloads its configuration and discovers
# the new "runsc-trace" runtime we just installed.
$ sudo systemctl restart docker

# Run a test container to trigger trace events and verify it works!
$ docker run --rm --runtime=runsc-trace hello-world
```

## Go Server Implementation

If you prefer to write your seccheck server in Go instead of C++, you can use
the reference Go server implementation located at
[`pkg/sentry/seccheck/sinks/remote/server/server.go`](https://cs.opensource.google/gvisor/gvisor/+/master:pkg/sentry/seccheck/sinks/remote/server/server.go).
It provides a robust, native sink to receive and process trace payloads.

## Learn More

To learn more about how `seccheck` works under the hood—including how to
discover trace points, configure advanced sessions dynamically, and understand
the core architecture—please refer to the full
[Seccheck Documentation](https://cs.opensource.google/gvisor/gvisor/+/master:pkg/sentry/seccheck/README.md).
