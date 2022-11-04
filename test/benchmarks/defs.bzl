"""Defines a rule for benchmark test targets."""

load("//tools:defs.bzl", "go_test")

def benchmark_test(name, tags = [], **kwargs):
    go_test(
        name,
        tags = [
            # Requires docker and runsc to be configured before the test runs.
            "local",
            "manual",
            "gvisor_benchmark",
        ],
        **kwargs
    )
