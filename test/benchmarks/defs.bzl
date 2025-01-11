"""Defines a rule for benchmark test targets."""

load("//tools:defs.bzl", "go_test")

def benchmark_test(name, tags = [], use_for_pgo = True, **kwargs):
    tags = tags + [
        # Requires docker and runsc to be configured before the test runs.
        "local",
        "manual",
        "gvisor_benchmark",
    ]
    if use_for_pgo:
        tags = tags + ["gvisor_pgo_benchmark"]
    go_test(
        name,
        tags = tags,
        # Benchmark test binaries are built inside a bazel docker container in
        # OSS but are executed directly on the host. Use static binaries to
        # avoid hitting glibc incompatibility.
        features = ["fully_static_link"],
        **kwargs
    )
