load("//test/runtimes:defs.bzl", "exclude_test", "runtime_test")

package(licenses = ["notice"])

go_binary(
    name = "runner",
    testonly = 1,
    srcs = ["runner.go"],
    visibility = ["//test/runtimes:__pkg__"],
    deps = [
        "//pkg/log",
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
    ],
)

runtime_test(
    name = "go1.12",
    exclude_file = "exclude/go1.12.csv",
    lang = "go",
    shard_count = 5,
)

runtime_test(
    name = "java11",
    exclude_file = "exclude/java11.csv",
    lang = "java",
    shard_count = 5,
)

runtime_test(
    name = "nodejs12.4.0",
    exclude_file = "exclude/nodejs12.4.0.csv",
    lang = "nodejs",
    shard_count = 5,
)

runtime_test(
    name = "php7.3.6",
    exclude_file = "exclude/php7.3.6.csv",
    lang = "php",
    shard_count = 5,
)

runtime_test(
    name = "python3.7.3",
    exclude_file = "exclude/python3.7.3.csv",
    lang = "python",
    shard_count = 5,
)

go_test(
    name = "exclude_test",
    size = "small",
    srcs = ["exclude_test.go"],
    library = ":runner",
)

exclude_test(
    name = "go",
    exclude_file = "exclude/go1.12.csv",
)

exclude_test(
    name = "java",
    exclude_file = "exclude/java11.csv",
)

exclude_test(
    name = "nodejs",
    exclude_file = "exclude/nodejs12.4.0.csv",
)

exclude_test(
    name = "php",
    exclude_file = "exclude/php7.3.6.csv",
)

exclude_test(
    name = "python",
    exclude_file = "exclude/python3.7.3.csv",
)
