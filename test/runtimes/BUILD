load("//test/runtimes:defs.bzl", "runtime_test")

package(licenses = ["notice"])

runtime_test(
    name = "go1.12",
    exclude_file = "exclude_go1.12.csv",
    lang = "go",
    shard_count = 5,
)

runtime_test(
    name = "java11",
    exclude_file = "exclude_java11.csv",
    lang = "java",
    shard_count = 10,
)

runtime_test(
    name = "nodejs12.4.0",
    exclude_file = "exclude_nodejs12.4.0.csv",
    lang = "nodejs",
    shard_count = 5,
)

runtime_test(
    name = "php7.3.6",
    exclude_file = "exclude_php7.3.6.csv",
    lang = "php",
    shard_count = 5,
)

runtime_test(
    name = "python3.7.3",
    exclude_file = "exclude_python3.7.3.csv",
    lang = "python",
    shard_count = 5,
)
