# Observability

[TOC]

This guide describes how to obtain Prometheus monitoring data from gVisor
sandboxes running with `runsc`.

**NOTE**: These metrics are mostly information about gVisor internals, and do
not provide introspection capabilities into the workload being sandboxed. If you
would like to monitor the sandboxed workload (e.g. for threat detection), refer
to **[Runtime Monitoring](runtime_monitoring.md)**.

`runsc` implements a
[Prometheus-compliant](https://prometheus.io/docs/instrumenting/exposition_formats/)
HTTP metric server using the `runsc metric-server` subcommand. This server is
meant to run **unsandboxed** as a sidecar process of your container runtime
(e.g. Docker).

## One-off metric export

You can export metric information from running sandboxes using the `runsc
export-metrics` subcommand. This does not require special configuration or
setting up a Prometheus server.

```
$ docker run -d --runtime=runsc --name=foobar debian sleep 1h
c7ce77796e0ece4c0881fb26261608552ea4a67b2fe5934658b8b4433e5190ed
$ sudo /path/to/runsc --root=/var/run/docker/runtime-runc/moby export-metrics c7ce77796e0ece4c0881fb26261608552ea4a67b2fe5934658b8b4433e5190ed
＃ Command-line export for sandbox c7ce77796e0ece4c0881fb26261608552ea4a67b2fe5934658b8b4433e5190ed
＃ Writing data from snapshot containing 175 data points taken at 2023-01-25 15:46:50.469403696 -0800 PST.


＃ HELP runsc_fs_opens Number of file opens.
＃ TYPE runsc_fs_opens counter
runsc_fs_opens{sandbox="c7ce77796e0ece4c0881fb26261608552ea4a67b2fe5934658b8b4433e5190ed"} 62 1674690410469

＃ HELP runsc_fs_read_wait Time waiting on file reads, in nanoseconds.
＃ TYPE runsc_fs_read_wait counter
runsc_fs_read_wait{sandbox="c7ce77796e0ece4c0881fb26261608552ea4a67b2fe5934658b8b4433e5190ed"} 0 1674690410469

＃ HELP runsc_fs_reads Number of file reads.
＃ TYPE runsc_fs_reads counter
runsc_fs_reads{sandbox="c7ce77796e0ece4c0881fb26261608552ea4a67b2fe5934658b8b4433e5190ed"} 54 1674690410469

＃ [...]
```

## Starting the metric server

Use the `runsc metric-server` subcommand:

```shell
$ sudo runsc \
    --root=/var/run/docker/runtime-runc/moby \
    --metric-server=localhost:1337 \
    metric-server
```

`--root` needs to be set to the OCI runtime root directory that your runtime
implementation uses. For Docker, this is typically
`/var/run/docker/runtime-runc/moby`; otherwise, if you already have gVisor set
up, you can use `ps aux | grep runsc` on the host to find the `--root` that a
running sandbox is using. This directory is typically only accessible by the
user Docker runs as (usually `root`), hence `sudo`. The metric server uses the
`--root` directory to scan for sandboxes running on the system.

The `--metric-server` flag is the network address or UDS path to bind to. In
this example, this will create a server bound on all interfaces on TCP port
`1337`. To listen on `lo` only, you could alternatively use
`--metric-server=localhost:1337`.

If something goes wrong, you may also want to add `--debug
--debug-log=/dev/stderr` to understand the metric server's behavior.

You can query the metric server with `curl`:

```
$ curl http://localhost:1337/metrics
＃ Data for runsc metric server exporting data for sandboxes in root directory /var/run/docker/runtime-runc/moby
＃ [...]

＃ HELP process_start_time_seconds Unix timestamp at which the process started. Used by Prometheus for counter resets.
＃ TYPE process_start_time_seconds gauge
process_start_time_seconds 1674598082.698509 1674598109532

＃ End of metric data.
```

## Starting sandboxes with metrics enabled

Sandbox metrics are disabled by default. To enable, add the flag
`--metric-server={ADDRESS}:{PORT}` to the runtime configuration. With Docker,
this can be set in `/etc/docker/daemon.json` like so:

```json
{
    "runtimes": {
        "runsc": {
            "path": "/path/to/runsc",
            "runtimeArgs": [
                "--metric-server=localhost:1337"
            ]
        }
    }
}
```

**NOTE**: The `--metric-server` flag value must be an exact string match between
the runtime configuration and the `runsc metric-server` command.

Once you've done this, you can start a container and see that it shows up in the
list of Prometheus metrics.

```
$ docker run -d --runtime=runsc --name=foobar debian sleep 1h
32beefcafe

$ curl http://localhost:1337/metrics
＃ Data for runsc metric server exporting data for sandboxes in root directory /var/run/docker/runtime-runc/moby
＃ Writing data from 3 snapshots: [...]


＃ HELP process_start_time_seconds Unix timestamp at which the process started. Used by Prometheus for counter resets.
＃ TYPE process_start_time_seconds gauge
process_start_time_seconds 1674599158.286067 1674599159819

＃ HELP runsc_fs_opens Number of file opens.
＃ TYPE runsc_fs_opens counter
runsc_fs_opens{iteration="42asdf",sandbox="32beefcafe"} 12 1674599159819

＃ HELP runsc_fs_read_wait Time waiting on file reads, in nanoseconds.
＃ TYPE runsc_fs_read_wait counter
runsc_fs_read_wait{iteration="42asdf",sandbox="32beefcafe"} 0 1674599159819

＃ [...]

＃ End of metric data.
```

Each per-container metric is labeled with at least:

-   `sandbox`: The container ID, in this case `32beefcafe`
-   `iteration`: A randomly-generated string (in this case `42asdf`) that stays
    constant for the lifetime of the sandbox. This helps distinguish between
    successive instances of the same sandbox with the same ID.

If you'd like to run some containers with metrics turned off and some on within
the same system, use two runtime entries in `/etc/docker/daemon.json` with only
one of them having the `--metric-server` flag set.

## Exporting data to Prometheus

The metric server exposes a
[standard `/metrics` HTTP endpoint](https://prometheus.io/docs/instrumenting/exposition_formats/)
on the address given by the `--metric-server` flag passed to `runsc
metric-server`. Simply point Prometheus at this address.

If desired, you can change the
[exporter name](https://prometheus.io/docs/instrumenting/writing_exporters/)
(prefix applied to all metric names) using the `--exporter-prefix` flag. It
defaults to `runsc_`.

The sandbox metrics exported may be filtered by using the optional `GET`
parameter `runsc-sandbox-metrics-filter`, e.g.
`/metrics?runsc-sandbox-metrics-filter=fs_.*`. Metric names must fully match
this regular expression. Note that this filtering is performed before prepending
`--exporter-prefix` to metric names.

The metric server also supports listening on a
[Unix Domain Socket](https://en.wikipedia.org/wiki/Unix_domain_socket). This can
be convenient to avoid reserving port numbers on the machine's network
interface, or for tighter control over who can read the data. Clients should
talk HTTP over this UDS. While Prometheus doesn't natively support reading
metrics from a UDS, this feature can be used in conjunction with a tool such as
[`socat` to re-expose this as a regular TCP port](https://serverfault.com/questions/517906/how-to-expose-a-unix-domain-socket-directly-over-tcp)
within another context (e.g. a tightly-managed network namespace that Prometheus
runs in).

```
$ sudo runsc --root=/var/run/docker/runtime-runc/moby --metric-server=/run/docker/runsc-metrics.sock metric-server &

$ sudo curl --unix-socket /run/docker/runsc-metrics.sock http://runsc-metrics/metrics
＃ Data for runsc metric server exporting data for sandboxes in root directory /var/run/docker/runtime-runc/moby
＃ [...]
＃ End of metric data.

＃ Set up socat to forward requests from *:1337 to /run/docker/runsc-metrics.sock in its own network namespace:
$ sudo unshare --net socat TCP-LISTEN:1337,reuseaddr,fork UNIX-CONNECT:/run/docker/runsc-metrics.sock &

＃ Set up basic networking for socat's network namespace:
$ sudo nsenter --net="/proc/$(pidof socat)/ns/net" sh -c 'ip link set lo up && ip route add default dev lo'

＃ Grab metric data from this namespace:
$ sudo nsenter --net="/proc/$(pidof socat)/ns/net" curl http://localhost:1337/metrics
＃ Data for runsc metric server exporting data for sandboxes in root directory /var/run/docker/runtime-runc/moby
＃ [...]
＃ End of metric data.
```

## Running the metric server in a sandbox

If you would like to run the metric server in a gVisor sandbox, you may do so,
provided that you give it access to the OCI runtime root directory, forward the
network port it binds to for external access, and enable host UDS support.

**WARNING**: Doing this does not provide you the full security of gVisor, as it
still grants the metric server full control over all running gVisor sandboxes on
the system. This step is only a defense-in-depth measure.

To do this, add a runtime with the `--host-uds=all` flag to
`/etc/docker/daemon.json`. The metric server needs the ability to open existing
UDSs (in order to communicate with running sandboxes), and to create new UDSs
(in order to create and listen on `/run/docker/runsc-metrics.sock`).

```json
{
    "runtimes": {
        "runsc": {
            "path": "/path/to/runsc",
            "runtimeArgs": [
                "--metric-server=/run/docker/runsc-metrics.sock"
            ]
        },
        "runsc-metric-server": {
            "path": "/path/to/runsc",
            "runtimeArgs": [
                "--metric-server=/run/docker/runsc-metrics.sock",
                "--host-uds=all"
            ]
        }
    }
}
```

Then start the metric server with this runtime, passing through the directories
containing the control files `runsc` uses to detect and communicate with running
sandboxes:

```shell
$ docker run -d --runtime=runsc-metric-server --name=runsc-metric-server \
    --volume="$(which runsc):/runsc:ro"  \
    --volume=/var/run/docker/runtime-runc/moby:/var/run/docker/runtime-runc/moby \
    --volume=/run/docker:/run/docker \
    --volume=/var/run:/var/run \
    alpine \
        /runsc \
            --root=/var/run/docker/runtime-runc/moby \
            --metric-server=/run/docker/runsc-metrics.sock \
            --debug --debug-log=/dev/stderr \
            metric-server
```

Yes, this means the metric server will report data about its own sandbox:

```
$ metric_server_id="$(docker inspect --format='{{.ID}}' runsc-metric-server)"
$ sudo curl --unix-socket /run/docker/runsc-metrics.sock http://runsc-metrics/metrics | grep "$metric_server_id"
＃   - Snapshot with 175 data points taken at 2023-01-25 15:45:33.70256855 -0800 -0800: map[iteration:2407456650315156914 sandbox:737ce142058561d764ad870d028130a29944821dd918c7979351b249d5d30481]
runsc_fs_opens{iteration="2407456650315156914",sandbox="737ce142058561d764ad870d028130a29944821dd918c7979351b249d5d30481"} 54 1674690333702
runsc_fs_read_wait{iteration="2407456650315156914",sandbox="737ce142058561d764ad870d028130a29944821dd918c7979351b249d5d30481"} 0 1674690333702
runsc_fs_reads{iteration="2407456650315156914",sandbox="737ce142058561d764ad870d028130a29944821dd918c7979351b249d5d30481"} 52 1674690333702
＃ [...]
```

## Labeling pods on Kubernetes

When using Kubernetes, users typically deal with pod names and container names.
On Kubelet machines, the underlying container names passed to the runtime are
non-human-friendly hexadecimal strings.

In order to provide more user-friendly labels, the metric server will pick up
the `io.kubernetes.cri.sandbox-name` and `io.kubernetes.cri.sandbox-namespace`
annotations provided by `containerd`, and automatically add these as labels
(`pod_name` and `namespace_name` respectively) for each per-sandbox metric.

## Metrics exported

The metric server exports a lot of gVisor-internal metrics, and generates its
own metrics as well. All metrics have documentation and type annotations in the
`/metrics` output, and this section aims to document some useful ones.

### Process-wide metrics

*   `process_start_time_seconds`: Unix timestamp representing the time at which
    the metric server started. This specific metric name is used by Prometheus,
    and as such its name is not affected by the `--exporter-prefix` flag. This
    metric is process-wide and has no labels.
*   `num_sandboxes_total`: A process-wide metric representing the total number
    of sandboxes that the metric server knows about.
*   `num_sandboxes_running`: A process-wide metric representing the number of
    running sandboxes that the metric server knows about.
*   `num_sandboxes_broken_metrics`: A process-wide metric representing the
    number of sandboxes from which the metric server could not get metric data.

### Per-sandbox metrics

*   `sandbox_presence`: A per-sandbox metric that is set to `1` for each sandbox
    that the metric server knows about. This can be used to join with other
    per-sandbox or per-pod metrics for which metric existence is not guaranteed.
*   `sandbox_running`: A per-sandbox metric that is set to `1` for each sandbox
    that the metric server knows about and that is actively running. This can be
    used in conjunction with `sandbox_presence` to determine the set of
    sandboxes that aren't running; useful if you want to alert about sandboxes
    that are down.
*   `sandbox_metadata`: A per-sandbox metric that carries a superset of the
    typical per-sandbox labels found on other per-sandbox metrics. These extra
    labels contain useful metadata about the sandbox, such as the version
    number, [platform](platforms.md), and [network type](networking.md) being
    used.
*   `sandbox_capabilities`: A per-sandbox, per-capability metric that carries
    the union of all capabilities present on at least one container of the
    sandbox. Can optionally be filtered to only a subset of capabilities using
    the `runsc-capability-filter` GET parameter on `/metrics` requests (regular
    expression). Useful for auditing and aggregating the capabilities you rely
    on across multiple sandboxes.
*   `sandbox_creation_time_seconds`: A per-sandbox Unix timestamp representing
    the time at which this sandbox was created.
