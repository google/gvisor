# gVisor Kubernetes benchmarks

The benchmarks in this directory are meant to run on a Kubernetes cluster
configured to run either gVisor or non-gVisor pods. These tests cannot run on
their own.

They currently only work for GKE clusters created with a specific set of
nodepools, which are used to distinguish which nodes the workload under test
runs. Specifically, you need:

*   A set of 1 or more nodes where cluster-wide system dependencies will run,
    such that all the other nodepools below do not run these cluster-wide
    dependencies in order to avoid adding noise to the benchmarks.
*   A set of 1 or more nodes labeled `nodepool-type=test-runtime-nodepool` and
    `cloud.google.com/gke-nodepool=test-runtime-nodepool`, where the workloads
    under test will run (e.g. `redis-server` for the Redis benchmark), and no
    other.
    *   These nodes should also be labeled `runtime=$RUNTIME`, where `$RUNTIME`
        is one of `runc`, `gvisor`, or their GPU/TPU-specific alternatives (see
        `testcluster/objects.go`). This will determine the default runtime used
        when benchmarking.
*   A set of 1 or more nodes labeled `nodepool-type=client-nodepool` and
    `cloud.google.com/gke-nodepool=client-nodepool`, where clients of the
    workloads under test will run (e.g. `redis-benchmark` for the Redis
    benchmark), and no other.
    *   These nodes may also be labeled `runtime=$RUNTIME`, but in most cases
        this should be `runc` to mimic the common case of non-gVisor-sandboxed
        clients.
*   Optional: A set of 1 or more nodes labeled `nodepool-type=tertiary-nodepool`
    and `cloud.google.com/gke-nodepool=tertiary-nodepool`, where backend
    dependencies of the workload under test will run (e.g. the MariaDB database
    for the WordPress/PHP benchmark), and no other (no cluster-wide system
    dependencies should run there to minimize benchmark noise).
    *   These nodes may also be labeled `runtime=$RUNTIME`; this label will have
        the same behavior as it does on other nodepools.
*   Optional: A set of 1 or more nodes labeled `nodepool-type=restore-nodepool`
    and `cloud.google.com/gke-nodepool=restore-nodepool`, where pods can be
    restored for tests involving pod snapshots. If this nodepool exists, its
    configuration will be identical to the `test-runtime-nodepool`, other than
    its name.

The cluster should also support setting `runtimeClassName` to `gvisor` to run
gVisor-sandboxed pods.

Once this cluster exists, dump its
[cluster proto](https://github.com/googleapis/googleapis/blob/master/google/container/v1/cluster_service.proto)
to a file, and ensure you can run workloads on this cluster via `kubectl`. Then,
you should be able to run benchmarks by pointing `--cluter-proto-path` to this
file, and `--kubectl-context-name` (set to the `kubectl` context name that
connects to this cluster in your `kubectl` config).
