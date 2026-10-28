"""Defines a rule for benchmark test targets."""

load("//tools:defs.bzl", "go_test")

def benchmark_test(name, tags = [], use_for_pgo = True, **kwargs):
    """Defines a benchmark test and its CI selection tags.

    Args:
      name: Name of the generated go_test target.
      tags: Additional target tags.
      use_for_pgo: Include the test in PGO benchmark selection.
      **kwargs: Additional arguments forwarded to go_test.
    """
    tags = tags + [
        "manual",
        "gvisor_benchmark",
    ]
    if use_for_pgo:
        tags = tags + ["gvisor_pgo_benchmark"]

    # Requires docker and runsc at execution time, not during compilation.
    kwargs["local"] = True
    go_test(
        name,
        tags = tags,
        # Benchmark test binaries are built inside a bazel docker container in
        # OSS but are executed directly on the host. Use static binaries to
        # avoid hitting glibc incompatibility.
        static = True,
        **kwargs
    )
