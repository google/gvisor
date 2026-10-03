load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "pac",
    srcs = [
        "pac_arm64.go",
        "pac_arm64.s",
        "pac_other.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/hostsyscall",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
