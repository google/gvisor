load("//test/runtimes:defs.bzl", "runtime_test")
load("//tools:defs.bzl", "bzl_library", "more_shards", "most_shards")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

runtime_test(
    name = "go1.22",
    exclude_file = "exclude/go1.22.csv",
    lang = "go",
    shard_count = more_shards,
)

runtime_test(
    name = "java21",
    batch = 100,
    exclude_file = "exclude/java21.csv",
    lang = "java",
    shard_count = most_shards,
)

runtime_test(
    name = "nodejs22.2.0",
    exclude_file = "exclude/nodejs22.2.0.csv",
    lang = "nodejs",
    shard_count = most_shards,
)

runtime_test(
    name = "php8.3.7",
    exclude_file = "exclude/php8.3.7.csv",
    lang = "php",
    shard_count = more_shards,
)

runtime_test(
    name = "python3.12.3",
    exclude_file = "exclude/python.csv",
    lang = "python",
    shard_count = more_shards,
)

bzl_library(
    name = "defs_bzl",
    srcs = ["defs.bzl"],
    visibility = ["//visibility:private"],
    deps = ["//tools:defs_bzl"],
)
