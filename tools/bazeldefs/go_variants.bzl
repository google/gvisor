"""Go tests with explicit target and execution architectures."""

load("@io_bazel_rules_go//go:def.bzl", "GoArchive", "GoLibrary", _go_test = "go_test")
load("//tools/bazeldefs:test_architectures.bzl", "with_test_architecture")

def _architecture_go_test(architecture):
    # When Bazel cannot extend go_test, with_cfg wraps it instead. Forward
    # its Go archive so Nogo can follow exports to the rule with the sources.
    return with_test_architecture(
        _go_test,
        architecture,
        extra_providers = [GoLibrary, GoArchive],
    ).build()

go_amd64_test, _go_amd64_transition = _architecture_go_test("amd64")
go_arm64_test, _go_arm64_transition = _architecture_go_test("arm64")
