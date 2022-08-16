This directory provides an example of a monitoring process that receives
connections from gVisor sandboxes and prints the traces to `stdout`. The example
contains two main files:

*   server.cc: this is where `main()` and all the code is. It sets up a server
    listening to a Unix-domain socket located at `/tmp/gvisor_events.sock` or a
    configurable location via a command line argument.
*   pod_init.json: this file contains the trace configuration that should be
    passed to `runsc`. It can be done either via `--pod-init-config` flag or
    using `runsc trace create` command. Note that the socket location is
    specified in this file, in case you change it.

# Usage

Let's first start the server, which waits for new connections:

```shell
$ bazel run examples/seccheck:server_cc
Socket address /tmp/gvisor_events.sock
```

Here is a simple example using `runsc do`:

```shell
runsc --rootless --network=none --pod-init-config=examples/seccheck/pod_init.json do echo 123
```

Back at the server terminal, you can see the following traces being outputted:

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

Connection messages indicate when `runsc` connected and disconnected to/from the
server. Then there is a trace for container start and a few syscalls to
`open(2)` for searching libraries. You can change `pod_init.json` to configure
the trace session to your liking.

To set this up with Docker, you can add the `--pod-init-config` flag when the
runtime is installed:

```shell
$ sudo runsc install --runtime=runsc-trace -- --pod-init-config=$PWD/examples/seccheck/pod_init.json
$ sudo systemctl restart docker
$ docker run --rm --runtime=runsc-trace hello-world
```
