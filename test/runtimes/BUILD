# These packages are used to run language runtime tests inside gVisor sandboxes.

load("@io_bazel_rules_go//go:def.bzl", "go_binary")
load("//test/runtimes:build_defs.bzl", "runtime_test")

package(licenses = ["notice"])

go_binary(
    name = "runner",
    testonly = 1,
    srcs = ["runner.go"],
    deps = [
        "//runsc/dockerutil",
        "//runsc/testutil",
    ],
)

runtime_test(
    image = "gcr.io/gvisor-presubmit/go1.12",
    lang = "go",
)

runtime_test(
    image = "gcr.io/gvisor-presubmit/java11",
    lang = "java",
)

runtime_test(
    image = "gcr.io/gvisor-presubmit/nodejs12.4.0",
    lang = "nodejs",
)

runtime_test(
    image = "gcr.io/gvisor-presubmit/php7.3.6",
    lang = "php",
)

runtime_test(
    image = "gcr.io/gvisor-presubmit/python3.7.3",
    lang = "python",
)
