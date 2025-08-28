# nftables Tests

nftables tests are run via `make nftables-tests`.

nftables require some extra Docker configuration to work. Enable IPv6 in
`/etc/docker/daemon.json` (make sure to restart Docker if you change this file):

```json
{
    "experimental": true,
    "fixed-cidr-v6": "2001:db8:1::/64",
    "ipv6": true,
    // Runtimes and other Docker config...
}
```

And if you're running manually (i.e. not using the `make` target), you'll need
to:

*   Enable nftables via `modprobe nfnetlink && modprobe nf_tables`.
*   Enable `--net-raw` in your chosen runtime in `/etc/docker/daemon.json` (make
    sure to restart Docker if you change this file).

The resulting runtime should look something like this:

```json
"runsc": {
    "path": "/tmp/nftables/runsc",
    "runtimeArgs": [
        "--debug-log",
        "/tmp/nftables/logs/runsc.log.%TEST%.%TIMESTAMP%.%COMMAND%",
        "--net-raw"
    ]
},
// ...
```

## Test Structure

Each test implements `TestCase`, providing (1) a function to run inside the
container and (2) a function to run locally. Those processes are given each
others' IP addresses. The test succeeds when both functions succeed.

The function inside the container (`ContainerAction`) typically sets some
nftables rules and then tries to send or receive packets. The local function
(`LocalAction`) will typically just send or receive packets.

### Adding Tests

1) Add your test to the `nftables` package.

2) Register the test in an `init` function via `RegisterTestCase` (see
`filter_input.go` as an example).

3) Add it to `nftables_test.go` (see the other tests in that file).

Your test is now runnable with bazel!

## Run individual tests

Build and install `runsc`. Re-run this when you modify gVisor:

```bash
$ bazel build //runsc && sudo cp bazel-out/k8-fastbuild-ST-4c64f0b3d5c7/bin/runsc/runsc_/runsc $(which runsc)
```

Build the testing Docker container. Re-run this when you modify the test code in
this directory:

```bash
$ make load-nftables
```

Run an individual test via:

```bash
$ bazel test //test/nftables:nftables_test --test_filter=<TESTNAME>
```

To run an individual test with `runc`:

```bash
$ bazel test //test/nftables:nftables_test --test_filter=<TESTNAME> --test_env=RUNTIME=runc
```
