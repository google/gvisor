load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "tools",
    srcs = [
        "ab.go",
        "fio.go",
        "hey.go",
        "iperf.go",
        "redis.go",
        "tools.go",
    ],
    visibility = ["//:sandbox"],
)

go_test(
    name = "tools_test",
    size = "small",
    srcs = [
        "ab_test.go",
        "fio_test.go",
        "hey_test.go",
        "iperf_test.go",
        "redis_test.go",
    ],
    library = ":tools",
)
