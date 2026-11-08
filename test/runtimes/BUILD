load("//test/runtimes:defs.bzl", "runtime_test")
load("//tools:defs.bzl", "bzl_library", "more_shards", "most_shards")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

runtime_test(
    name = "go1.22",
    args = [
        "--lang",
        "go",
        "--exclude_file",
        "$(rootpath :exclude/go1.22.csv)",
    ],
    data = ["exclude/go1.22.csv"],
    shard_count = more_shards,
)

runtime_test(
    name = "java21",
    args = [
        "--lang",
        "java",
        "--batch",
        "100",
        "--exclude_file",
        "$(rootpath :exclude/java21.csv)",
    ],
    data = ["exclude/java21.csv"],
    shard_count = most_shards,
)

runtime_test(
    name = "nodejs22.2.0",
    args = [
        "--lang",
        "nodejs",
        "--exclude_file",
        "$(rootpath :exclude/nodejs22.2.0.csv)",
    ],
    data = ["exclude/nodejs22.2.0.csv"],
    shard_count = most_shards,
)

runtime_test(
    name = "php8.5.11",
    args = [
        "--lang",
        "php",
    ],
    shard_count = more_shards,
)

runtime_test(
    name = "python3.12.3",
    args = [
        "--lang",
        "python",
        "--exclude_file",
        "$(rootpath :exclude/python.csv)",
    ],
    data = ["exclude/python.csv"],
    shard_count = more_shards,
)

bzl_library(
    name = "defs_bzl",
    srcs = ["defs.bzl"],
    visibility = ["//visibility:private"],
    deps = [
        "//tools:defs_bzl",
        "@bazel_skylib//rules:native_binary",
    ],
)
