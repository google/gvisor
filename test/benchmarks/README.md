# Benchmark tools

This package and subpackages are for running macro benchmarks on `runsc`. They
are meant to replace the previous //benchmarks benchmark-tools written in
python.

Benchmarks are meant to look like regular golang benchmarks using the testing.B
library.

## Setup

To run benchmarks you will need:

*   Docker installed (17.09.0 or greater).

The easiest way to run benchmarks is to use the script at
//scripts/benchmark.sh.

If not using the script, you will need:

*   `runsc` configured with docker

Note: benchmarks call the runtime by name. If docker can run it with
`--runtime=` flag, these tools should work.

## Running benchmarks

The easiest way to run is with the script at //scripts/benchmarks.sh. The script
will run all benchmarks under //test/benchmarks if a target is not provided.

```bash
./script/benchmarks.sh //path/to/target
```

If you want to run benchmarks manually:

*   Run `make load-all-images` from `//`
*   Run with:

```bash
bazel test --test_arg=--runtime=RUNTIME -c opt --test_output=streamed --test_timeout=600 --test_arg=-test.bench=. --nocache_test_results //path/to/target
```

## Writing benchmarks

Benchmarks consist of docker images as Dockerfiles and golang testing.B
benchmarks.

### Dockerfiles:

*   Are stored at //images.
*   New Dockerfiles go in an appropriately named directory at
    `//images/benchmarks/my-cool-dockerfile`.
*   Dockerfiles for benchmarks should:
    *   Use explicitly versioned packages.
    *   Not use ENV and CMD statements...it is easy to add these in the API.
*   Note: A common pattern for getting access to a tmpfs mount is to copy files
    there after container start. See: //test/benchmarks/build/bazel_test.go. You
    can also make your own with `RunOpts.Mounts`.

### testing.B packages

In general, benchmarks should look like this:

```golang

var h harness.Harness

func BenchmarkMyCoolOne(b *testing.B) {
  machine, err := h.GetMachine()
  // check err

  ctx := context.Background()
  container := machine.GetContainer(ctx, b)
  defer container.CleanUp(ctx)

  b.ResetTimer()

  //Respect b.N.
  for i := 0; i < b.N; i++ {
    out, err := container.Run(ctx, dockerutil.RunOpts{
      Image: "benchmarks/my-cool-image",
      Env: []string{"MY_VAR=awesome"},
      other options...see dockerutil
    }, "sh", "-c", "echo MY_VAR" ...)
    //check err
    b.StopTimer()

    // Do parsing and reporting outside of the timer.
    number := parseMyMetric(out)
    b.ReportMetric(number, "my-cool-custom-metric")

    b.StartTimer()
  }
}

func TestMain(m *testing.M) {
    h.Init()
    os.Exit(m.Run())
}
```

Some notes on the above:

*   The harness is initiated in the TestMain method and made global to test
    module. The harness will handle any presetup that needs to happen with
    flags, remote virtual machines (eventually), and other services.
*   Respect `b.N` in that users of the benchmark may want to "run for an hour"
    or something of the sort.
*   Use the `b.ReportMetric` method to report custom metrics.
*   Set the timer if time is useful for reporting. There isn't a way to turn off
    default metrics in testing.B (B/op, allocs/op, ns/op).
*   Take a look at dockerutil at //pkg/test/dockerutil to see all methods
    available from containers. The API is based on the "official"
    [docker API for golang](https://pkg.go.dev/mod/github.com/docker/docker).
*   `harness.GetMachine` marks how many machines this tests needs. If you have a
    client and server and to mark them as multiple machines, call it
    `GetMachine` twice.
