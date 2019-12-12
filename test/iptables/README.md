# iptables Tests

iptables tests are run via `scripts/iptables\_test.sh`.

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

Build the testing Docker container:

```bash
$ bazel run //test/iptables/runner -- --norun
```

Run an individual test via:

```bash
$ bazel test //test/iptables:iptables_test --test_filter=<TESTNAME>
```

To run an individual test with `runc`:

```bash
$ bazel test //test/iptables:iptables_test --test_filter=<TESTNAME> --test_arg=--runtime=runc
```
