load("//tools:defs.bzl", "bzl_library", "more_shards", "most_shards")
load("//test/runtimes:defs.bzl", "runtime_test")

package(licenses = ["notice"])

runtime_test(
    name = "go1.12",
    exclude_file = "exclude/go1.12.csv",
    lang = "go",
    shard_count = more_shards,
)

runtime_test(
    name = "java11",
    batch = 100,
    exclude_file = "exclude/java11.csv",
    lang = "java",
    shard_count = most_shards,
)

runtime_test(
    name = "nodejs12.4.0",
    exclude_file = "exclude/nodejs12.4.0.csv",
    lang = "nodejs",
    shard_count = most_shards,
)

runtime_test(
    name = "php7.3.6",
    exclude_file = "exclude/php7.3.6.csv",
    lang = "php",
    shard_count = more_shards,
)

runtime_test(
    name = "python3.7.3",
    exclude_file = "exclude/python3.7.3.csv",
    lang = "python",
    shard_count = more_shards,
)

bzl_library(
    name = "defs_bzl",
    srcs = ["defs.bzl"],
    visibility = ["//visibility:private"],
)
