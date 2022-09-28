load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "tools",
    testonly = 1,
    srcs = [
        "ab.go",
        "fio.go",
        "hackbench.go",
        "hey.go",
        "iperf.go",
        "meminfo.go",
        "parser_util.go",
        "redis.go",
        "sysbench.go",
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
        "meminfo_test.go",
        "redis_test.go",
        "sysbench_test.go",
    ],
    library = ":tools",
)
