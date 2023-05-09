# Benchmark tools

This package and subpackages are for running macro benchmarks on `runsc`. They
are meant to replace the previous //benchmarks benchmark-tools written in
python.

Benchmarks are meant to look like regular golang benchmarks using the testing.B
library.

## Setup

To run benchmarks you will need:

*   Docker installed (17.09.0 or greater).

## Running benchmarks

To run, use the Makefile:

-   Install runsc as a runtime: `make dev`
    -   The above command will place several configurations of runsc in your
        /etc/docker/daemon.json file. Choose one without the debug option set.
-   Run your benchmark: `make run-benchmark
    RUNTIME=[RUNTIME_FROM_DAEMON.JSON/runc] BENCHMARKS_TARGETS=path/to/target`
-   Additionally, you can benchmark several platforms in one command:

```
make benchmark-platforms BENCHMARKS_TARGET=path/to/target
```

The above command will install runtimes/run benchmarks on ptrace and kvm as well
as run the benchmark on native runc.

Benchmarks are run with root as some benchmarks require root privileges to do
things like drop caches.

## Writing benchmarks

Benchmarks consist of docker images as Dockerfiles and golang testing.B
benchmarks.

### Dockerfiles:

*   Are stored at //images.
*   New Dockerfiles go in an appropriately named directory at
    `//images/benchmarks/my-cool-dockerfile`.
*   Dockerfiles for benchmarks should:
    *   Use explicitly versioned packages.
    *   Don't use ENV and CMD statements. It is easy to add these in the API via
        `dockerutil.RunOpts`.
*   Note: A common pattern for getting access to a tmpfs mount is to copy files
    there after container start. See: //test/benchmarks/build/bazel_test.go. You
    can also make your own with `RunOpts.Mounts`.

### testing.B packages

In general, benchmarks should look like this:

```golang
func BenchmarkMyCoolOne(b *testing.B) {
  machine, err := harness.GetMachine()
  // check err
  defer machine.CleanUp()

  ctx := context.Background()
  container := machine.GetContainer(ctx, b)
  defer container.CleanUp(ctx)

  b.ResetTimer()

  // Respect b.N.
  for i := 0; i < b.N; i++ {
    out, err := container.Run(ctx, dockerutil.RunOpts{
      Image: "benchmarks/my-cool-image",
      Env: []string{"MY_VAR=awesome"},
      // other options...see dockerutil
    }, "sh", "-c", "echo MY_VAR")
    // check err...
    b.StopTimer()

    // Do parsing and reporting outside of the timer.
    number := parseMyMetric(out)
    b.ReportMetric(number, "my-cool-custom-metric")

    b.StartTimer()
  }
}

func TestMain(m *testing.M) {
    harness.Init()
    os.Exit(m.Run())
}
```

Some notes on the above:

*   Respect and linearly scale by `b.N` so that users can run a number of times
    (--benchtime=10x) or for a time duration (--benchtime=1m). For many
    benchmarks, this is just the runtime of the container under test. Sometimes
    this is a parameter to the container itself. For Example, the httpd
    benchmark (and most client server benchmarks) uses b.N as a parameter to the
    Client container that specifies how many requests to make to the server.
*   Use the `b.ReportMetric()` method to report custom metrics.
*   Never turn off the timer (b.N), but set and reset it if useful for the
    benchmark. There isn't a way to turn off default metrics in testing.B (B/op,
    allocs/op, ns/op).
*   Take a look at dockerutil at //pkg/test/dockerutil to see all methods
    available from containers. The API is based on the "official"
    [docker API for golang](https://pkg.go.dev/mod/github.com/docker/docker).
*   `harness.GetMachine()` marks how many machines this tests needs. If you have
    a client and server and to mark them as multiple machines, call
    `harness.GetMachine()` twice.

## Profiling

For profiling, the runtime is required to have the `--profile` flag enabled.
This flag loosens seccomp filters so that the runtime can write profile data to
disk. This configuration is not recommended for production.

To profile, simply run the `benchmark-platforms` command from above and profiles
will be in /tmp/profile.

Or run with: `make run-benchmark RUNTIME=[RUNTIME_UNDER_TEST]
BENCHMARKS_TARGETS=path/to/target`

Profiles will be in /tmp/profile. Note: runtimes must have the `--profile` flag
set in /etc/docker/daemon.conf and profiling will not work on runc.
