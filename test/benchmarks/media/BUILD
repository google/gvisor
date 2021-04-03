load("//tools:defs.bzl", "go_library")
load("//test/benchmarks:defs.bzl", "benchmark_test")

package(licenses = ["notice"])

go_library(
    name = "media",
    testonly = 1,
    srcs = ["media.go"],
)

benchmark_test(
    name = "ffmpeg_test",
    srcs = ["ffmpeg_test.go"],
    library = ":media",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//test/benchmarks/harness",
    ],
)
