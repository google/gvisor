# Benchmark tools

These scripts are tools for collecting performance data for Docker-based tests.

## Setup

The scripts assume the following:

*   There are two sets of machines: one where the scripts will be run
    (controller) and one or more machines on which docker containers will be run
    (environment).
*   The controller machine must have bazel installed along with this source
    code. You should be able to run a command like `bazel run //benchmarks --
    --list`
*   Environment machines must have docker and the required runtimes installed.
    More specifically, you should be able to run a command like: `docker run
    --runtime=$RUNTIME your/image`.
*   The controller has ssh private key which can be used to login to environment
    machines and run docker commands without using `sudo`. This is not required
    if running locally via the `run-local` command.
*   The docker daemon on each of your environment machines is listening on
    `unix:///var/run/docker.sock` (docker's default).

For configuring the environment manually, consult the
[dockerd documentation][dockerd].

## Running benchmarks

### Locally

The tool is built to, by default, use Google Cloud Platform to run benchmarks,
but it does support GCP workflows. To run locally, run the following from the
benchmarks directory:

```bash
bazel run --define gcloud=off //benchmarks -- run-local startup

...
method,metric,result
startup.empty,startup_time_ms,652.5772
startup.node,startup_time_ms,1654.4042000000002
startup.ruby,startup_time_ms,1429.835
```

The above command ran the startup benchmark locally, which consists of three
benchmarks (empty, node, and ruby). Benchmark tools ran it on the default
runtime, runc. Running on another installed runtime, like say runsc, is as
simple as:

```bash
bazel run  --define gcloud=off //benchmarks -- run-local startup --runtime=runsc
```

There is help:

```bash
bazel run --define gcloud=off //benchmarks -- --help
bazel run --define gcloud=off //benchmarks -- run-local --help
```

To list available benchmarks, use the `list` commmand:

```bash
bazel --define gcloud=off  run //benchmarks -- list

...
Benchmark: sysbench.cpu
Metrics: events_per_second
    Run sysbench CPU test. Additional arguments can be provided for sysbench.

    :param max_prime: The maximum prime number to search.
```

You can choose benchmarks by name or regex like:

```bash
bazel run --define gcloud=off //benchmarks -- run-local startup.node
...
metric,result
startup_time_ms,1671.7178000000001

```

or

```bash
bazel run --define gcloud=off //benchmarks -- run-local s
...
method,metric,result
startup.empty,startup_time_ms,1792.8292
startup.node,startup_time_ms,3113.5274
startup.ruby,startup_time_ms,3025.2424
sysbench.cpu,cpu_events_per_second,12661.47
sysbench.memory,memory_ops_per_second,7228268.44
sysbench.mutex,mutex_time,17.4835
sysbench.mutex,mutex_latency,3496.7
sysbench.mutex,mutex_deviation,0.04
syscall.syscall,syscall_time_ns,2065.0
```

You can run parameterized benchmarks, for example to run with different
runtimes:

```bash
bazel run --define gcloud=off //benchmarks -- run-local --runtime=runc --runtime=runsc sysbench.cpu
```

Or with different parameters:

```bash
bazel run --define gcloud=off //benchmarks -- run-local --max_prime=10 --max_prime=100 sysbench.cpu
```

### On Google Compute Engine (GCE)

Benchmarks may be run on GCE in an automated way. The default project configured
for `gcloud` will be used.

An additional parameter `installers` may be provided to ensure that the latest
runtime is installed from the workspace. See the files in `tools/installers` for
supported install targets.

```bash
bazel run //benchmarks -- run-gcp --installers=head --runtime=runsc sysbench.cpu
```

When running on GCE, the scripts generate a per run SSH key, which is added to
your project. The key is set to expire in GCE after 60 minutes and is stored in
a temporary directory on the local machine running the scripts.

## Writing benchmarks

To write new benchmarks, you should familiarize yourself with the structure of
the repository. There are three key components.

## Harness

The harness makes use of the [docker py SDK][docker-py]. It is advisable that
you familiarize yourself with that API when making changes, specifically:

*   clients
*   containers
*   images

In general, benchmarks need only interact with the `Machine` objects provided to
the benchmark function, which are the machines defined in the environment. These
objects allow the benchmark to define the relationships between different
containers, and parse the output.

## Workloads

The harness requires workloads to run. These are all available in the
`workloads` directory.

In general, a workload consists of a Dockerfile to build it (while these are not
hermetic, in general they should be as fixed and isolated as possible), some
parsers for output if required, parser tests and sample data. Provided the test
is named after the workload package and contains a function named `sample`, this
variable will be used to automatically mock workload output when the `--mock`
flag is provided to the main tool.

## Writing benchmarks

Benchmarks define the tests themselves. All benchmarks have the following
function signature:

```python
def my_func(output) -> float:
    return float(output)

@benchmark(metrics = my_func, machines = 1)
def my_benchmark(machine: machine.Machine, arg: str):
    return "3.4432"
```

Each benchmark takes a variable amount of position arguments as
`harness.Machine` objects and some set of keyword arguments. It is recommended
that you accept arbitrary keyword arguments and pass them through when
constructing the container under test.

To write a new benchmark, open a module in the `suites` directory and use the
above signature. You should add a descriptive doc string to describe what your
benchmark is and any test centric arguments.

[dockerd]: https://docs.docker.com/engine/reference/commandline/dockerd/
[docker-py]: https://docker-py.readthedocs.io/en/stable/
