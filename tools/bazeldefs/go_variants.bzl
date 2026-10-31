"""Go tests with explicit target and execution architectures."""

load("@io_bazel_rules_go//go:def.bzl", "GoArchive", "GoLibrary", _go_test = "go_test")
load("//tools/bazeldefs:test_architectures.bzl", "with_test_architecture")

def _compile_go_test(compile_exec_compatible_with, **kwargs):
    kwargs["exec_compatible_with"] = compile_exec_compatible_with
    _go_test(**kwargs)

def _architecture_go_test(architecture):
    # Reuse with_cfg's test frontend: it forwards runfiles, environment,
    # coverage and test attributes while only runtime execution is constrained.
    # Nogo follows the forwarded GoArchive through exports to the original test.
    return with_test_architecture(
        _compile_go_test,
        architecture,
        extra_providers = [GoLibrary, GoArchive],
    ).build()

go_amd64_test, _go_amd64_transition = _architecture_go_test("amd64")
go_arm64_test, _go_arm64_transition = _architecture_go_test("arm64")
