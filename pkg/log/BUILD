load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "log",
    srcs = [
        "glog.go",
        "glog_unsafe.go",
        "json.go",
        "json_k8s.go",
        "log.go",
    ],
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//pkg/linewriter",
        "//pkg/sync",
    ],
)

go_test(
    name = "log_test",
    size = "small",
    srcs = [
        "json_test.go",
        "log_test.go",
    ],
    library = ":log",
)
