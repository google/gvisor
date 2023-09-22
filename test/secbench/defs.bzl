"""Defines secbench_test, a wrapper over go_test for secbench benchmarks."""

load("//tools:defs.bzl", "go_test")

def secbench_test(**kwargs):
    """Wrapper over go_test useful for secbench benchmarks.

    Args:
      **kwargs: Same as go_test arguments.
    """
    kwargs["tags"] = kwargs.get("tags", []) + [
        "local",
        "manual",
        "secbench",
    ]
    kwargs["static"] = True
    kwargs["timeout"] = "long"
    go_test(**kwargs)
