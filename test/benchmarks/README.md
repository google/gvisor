# Benchmark tools

This package and subpackages are for running macro benchmarks on `runsc`. They
are meant to replace the previous //benchmarks benchmark-tools written in
python.

Benchmarks are meant to look like regular golang benchmarks using the testing.B
library.

## Setup

To run benchmarks you will need:

*   Docker installed (17.09.0 or greater).

The easiest way to setup runsc for running benchmarks is to use the make file.
From the root directory:

*   Download images: `make load-all-images`
*   Install runsc suitable for benchmarking, which should probably not have
    strace or debug logs enabled. For example: `make configure RUNTIME=myrunsc
    ARGS=--platform=kvm`.
*   Restart docker: `sudo service docker restart`

You should now have a runtime with the following options configured in
`/etc/docker/daemon.json`

```
"myrunsc": {
            "path": "/tmp/myrunsc/runsc",
            "runtimeArgs": [
                "--debug-log",
                "/tmp/bench/logs/runsc.log.%TEST%.%TIMESTAMP%.%COMMAND%",
                "--platform=kvm"
            ]
        },

```

This runtime has been configured with a debugging off and strace logs off and is
using kvm for demonstration.

## Running benchmarks

Given the runtime above runtime `myrunsc`, run benchmarks with the following:

```
make sudo TARGETS=//path/to:target ARGS="--runtime=myrunsc -test.v \
  -test.bench=." OPTIONS="-c opt"
```

For example, to run only the Iperf tests:

```
make sudo TARGETS=//test/benchmarks/network:network_test \
  ARGS="--runtime=myrunsc -test.v -test.bench=Iperf" OPTIONS="-c opt"
```

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
    *   Not use ENV and CMD statements...it is easy to add these in the API.
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
      other options...see dockerutil
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

*   Respect `b.N` in that users of the benchmark may want to "run for an hour"
    or something of the sort.
*   Use the `b.ReportMetric()` method to report custom metrics.
*   Set the timer if time is useful for reporting. There isn't a way to turn off
    default metrics in testing.B (B/op, allocs/op, ns/op).
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

*   Install runsc with the `--profile` flag: `make configure RUNTIME=myrunsc
    ARGS="--profile --platform=kvm --vfs2"`. The kvm and vfs2 flags are not
    required, but are included for demonstration.
*   Restart docker: `sudo service docker restart`

To run and generate CPU profiles fs_test test run:

```
make sudo TARGETS=//test/benchmarks/fs:fs_test \
  ARGS="--runtime=myrunsc -test.v -test.bench=. --pprof-cpu" OPTIONS="-c opt"
```

Profiles would be at: `/tmp/profile/myrunsc/CONTAINERNAME/cpu.pprof`
