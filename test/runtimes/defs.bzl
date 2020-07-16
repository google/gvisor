"""Defines a rule for runtime test targets."""

load("//tools:defs.bzl", "go_test")

def runtime_test(name, lang, exclude_file, **kwargs):
    go_test(
        name = name,
        srcs = ["runner.go"],
        args = [
            "--lang",
            lang,
            "--image",
            name,  # Resolved as images/runtimes/%s.
            "--exclude_file",
            "test/runtimes/" + exclude_file,
        ],
        data = [
            exclude_file,
            "//test/runtimes/proctor",
        ],
        defines_main = 1,
        tags = [
            "local",
            "manual",
        ],
        deps = [
            "//pkg/log",
            "//pkg/test/dockerutil",
            "//pkg/test/testutil",
        ],
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
