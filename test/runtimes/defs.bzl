"""Defines a rule for runtime test targets."""

load("@bazel_skylib//rules:native_binary.bzl", "native_test")
load("//tools:defs.bzl", "go_test", "local_test_tags")

def runtime_test(name, args, data = [], **kwargs):
    """Run the language tests in images/runtimes/{name}."""
    native_test(
        name = name,
        src = "//test/runtimes/runner:runner",
        out = name + "-executer",
        args = ["--image", name] + args,
        # Include the release to invalidate test results when runsc changes.
        data = ["//:release", "//test/runtimes/proctor:proctor_bin"] + data,
        tags = [
            "no-sandbox",
            "manual",
        ] + local_test_tags,
        **kwargs
    )

def exclude_test(name, exclude_file):
    """Test that a exclude file parses correctly."""
    go_test(
        name = name + "_exclude_test",
        library = ":runner",
        srcs = ["exclude_test.go"],
        args = ["--exclude_file", "test/runtimes/" + exclude_file],
        data = [exclude_file],
    )
