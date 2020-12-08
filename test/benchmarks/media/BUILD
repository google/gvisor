load("//tools:defs.bzl", "go_library")
load("//test/benchmarks:defs.bzl", "benchmark_test")

package(licenses = ["notice"])

go_library(
    name = "media",
    testonly = 1,
    srcs = ["media.go"],
    deps = ["//test/benchmarks/harness"],
)

benchmark_test(
    name = "media_test",
    size = "large",
    srcs = ["ffmpeg_test.go"],
    library = ":media",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//test/benchmarks/harness",
    ],
)
