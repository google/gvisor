"""Defines a rule for runsc test targets."""

load("@io_bazel_rules_go//go:def.bzl", _go_test = "go_test")

# runtime_test is a macro that will create targets to run the given test target
# with different runtime options.
def runtime_test(**kwargs):
    """Runs the given test target with different runtime options."""
    name = kwargs["name"]
    _go_test(**kwargs)
    kwargs["name"] = name + "_hostnet"
    kwargs["args"] = ["--runtime-type=hostnet"]
    _go_test(**kwargs)
    kwargs["name"] = name + "_kvm"
    kwargs["args"] = ["--runtime-type=kvm"]
    _go_test(**kwargs)
    kwargs["name"] = name + "_overlay"
    kwargs["args"] = ["--runtime-type=overlay"]
    _go_test(**kwargs)
