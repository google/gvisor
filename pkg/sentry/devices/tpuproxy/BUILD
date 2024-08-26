load("//tools:defs.bzl", "go_library", "go_test")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "tpuproxy",
    srcs = [
        "seccomp_filter.go",
        "tpuproxy.go",
    ],
    visibility = [
        "//pkg/sentry:internal",
    ],
    deps = [
        "//pkg/abi/gasket",
        "//pkg/abi/linux",
        "//pkg/abi/tpu",
        "//pkg/seccomp",
        "//pkg/sentry/devices/tpuproxy/accel",
        "//pkg/sentry/devices/tpuproxy/vfio",
        "//pkg/sentry/vfs",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "tpuproxy_test",
    srcs = ["tpuproxy_test.go"],
    library = ":tpuproxy",
)
