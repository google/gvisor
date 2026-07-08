"""Defines the compatibility_test macro for application compatibility tests."""

load("//tools:defs.bzl", "go_test")

# Runtimes under which compatibility tests are run, as (target suffix, runtime)
# pairs. "native" is the unsandboxed baseline (runc), matching the naming used by
# the syscall tests; "runsc" is gVisor.
_RUNTIMES = [
    ("native", "runc"),
    ("runsc", "runsc"),
]

def compatibility_test(name, srcs, deps = [], data = [], tags = [], size = "large", **kwargs):
    """compatibility_test generates one go_test target per runtime.

    For <name> it generates:
      <name>_native: runs the test under runc (as a baseline).
      <name>_runsc:  runs the test under runsc.

    Both targets share the same sources and differ only in the "--runtime"
    argument passed to the test binary (which dockerutil.MakeContainer reads).

    Args:
      name: base name; per-runtime targets append "_native"/"_runsc".
      srcs: test sources.
      deps: test dependencies.
      data: runtime data dependencies.
      tags: extra tags (in addition to "local" and "manual").
      size: test size (default "large").
      **kwargs: forwarded to go_test (e.g. visibility).
    """
    for suffix, runtime in _RUNTIMES:
        target_data = list(data)
        if runtime != "runc":
            # runsc is needed to invalidate the bazel cache on any code change.
            target_data = target_data + ["//runsc"]
        go_test(
            name = name + "_" + suffix,
            srcs = srcs,
            size = size,
            args = ["--runtime=" + runtime],
            data = target_data,
            tags = tags + ["local", "manual"],
            deps = deps,
            **kwargs
        )
