# These packages are used to run language runtime tests inside gVisor sandboxes.

load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_test")
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
    blacklist_file = "blacklist_go1.12.csv",
    image = "gcr.io/gvisor-presubmit/go1.12",
    lang = "go",
)

runtime_test(
    blacklist_file = "blacklist_java11.csv",
    image = "gcr.io/gvisor-presubmit/java11",
    lang = "java",
)

runtime_test(
    blacklist_file = "blacklist_nodejs12.4.0.csv",
    image = "gcr.io/gvisor-presubmit/nodejs12.4.0",
    lang = "nodejs",
)

runtime_test(
    blacklist_file = "blacklist_php7.3.6.csv",
    image = "gcr.io/gvisor-presubmit/php7.3.6",
    lang = "php",
)

runtime_test(
    blacklist_file = "blacklist_python3.7.3.csv",
    image = "gcr.io/gvisor-presubmit/python3.7.3",
    lang = "python",
)

go_test(
    name = "blacklist_test",
    size = "small",
    srcs = ["blacklist_test.go"],
    embed = [":runner"],
)
