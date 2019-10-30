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
    name = "go1.12",
    blacklist_file = "blacklist_go1.12.csv",
    lang = "go",
)

runtime_test(
    name = "java11",
    blacklist_file = "blacklist_java11.csv",
    lang = "java",
)

runtime_test(
    name = "nodejs12.4.0",
    blacklist_file = "blacklist_nodejs12.4.0.csv",
    lang = "nodejs",
)

runtime_test(
    name = "php7.3.6",
    blacklist_file = "blacklist_php7.3.6.csv",
    lang = "php",
)

runtime_test(
    name = "python3.7.3",
    blacklist_file = "blacklist_python3.7.3.csv",
    lang = "python",
)

go_test(
    name = "blacklist_test",
    size = "small",
    srcs = ["blacklist_test.go"],
    embed = [":runner"],
)
