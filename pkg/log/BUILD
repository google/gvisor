load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

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
    importpath = "gvisor.dev/gvisor/pkg/log",
    visibility = [
        "//visibility:public",
    ],
    deps = ["//pkg/linewriter"],
)

go_test(
    name = "log_test",
    size = "small",
    srcs = [
        "json_test.go",
        "log_test.go",
    ],
    embed = [":log"],
)
