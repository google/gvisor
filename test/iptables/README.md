# iptables Tests

iptables tests are run via `scripts/iptables_test.sh`.

iptables requires raw socket support, so you must add the `--net-raw=true` flag
to `/etc/docker/daemon.json` in order to use it.

## Test Structure

Each test implements `TestCase`, providing (1) a function to run inside the
container and (2) a function to run locally. Those processes are given each
others' IP addresses. The test succeeds when both functions succeed.

The function inside the container (`ContainerAction`) typically sets some
iptables rules and then tries to send or receive packets. The local function
(`LocalAction`) will typically just send or receive packets.

### Adding Tests

1) Add your test to the `iptables` package.

2) Register the test in an `init` function via `RegisterTestCase` (see
`filter_input.go` as an example).

3) Add it to `iptables_test.go` (see the other tests in that file).

Your test is now runnable with bazel!

## Run individual tests

Build and install `runsc`. Re-run this when you modify gVisor:

```bash
$ bazel build //runsc && sudo cp bazel-bin/runsc/linux_amd64_pure_stripped/runsc $(which runsc)
```

Build the testing Docker container. Re-run this when you modify the test code in
this directory:

```bash
$ make load-iptables
```

Run an individual test via:

```bash
$ bazel test //test/iptables:iptables_test --test_filter=<TESTNAME>
```

To run an individual test with `runc`:

```bash
$ bazel test //test/iptables:iptables_test --test_filter=<TESTNAME> --test_arg=--runtime=runc
```
