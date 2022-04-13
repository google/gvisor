load("//tools:defs.bzl", "bzl_library", "more_shards", "most_shards")
load("//test/runtimes:defs.bzl", "runtime_test")

package(licenses = ["notice"])

runtime_test(
    name = "go1.16",
    exclude_file = "exclude/go1.16.csv",
    lang = "go",
    shard_count = more_shards,
)

runtime_test(
    name = "java17",
    batch = 100,
    exclude_file = "exclude/java17.csv",
    lang = "java",
    shard_count = most_shards,
)

runtime_test(
    name = "nodejs16.13.2",
    exclude_file = "exclude/nodejs16.13.2.csv",
    lang = "nodejs",
    shard_count = most_shards,
)

runtime_test(
    name = "php8.1.1",
    exclude_file = "exclude/php8.1.1.csv",
    lang = "php",
    shard_count = more_shards,
)

runtime_test(
    name = "python3.10.2",
    exclude_file = "exclude/python3.10.2.csv",
    lang = "python",
    shard_count = more_shards,
)

bzl_library(
    name = "defs_bzl",
    srcs = ["defs.bzl"],
    visibility = ["//visibility:private"],
)
