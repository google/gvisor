load("//tools:defs.bzl", "go_binary", "go_test", "local_test_tags", "more_shards")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "runner",
    srcs = ["moby_runner.go"],
    static = True,
    deps = [
        "//test/runtimes/proctor",
        "//test/runtimes/proctor/lib",
    ],
)

go_test(
    name = "moby",
    srcs = ["moby_test.go"],
    data = [
        ":runner",
        "//runsc",
    ],
    shard_count = more_shards,
    tags = [
        "external",
        "manual",
        "no-sandbox",
    ] + local_test_tags,
    deps = [
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
        "//test/runtimes/runner/lib",
    ],
)
