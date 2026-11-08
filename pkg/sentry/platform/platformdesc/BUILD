load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "platformdesc",
    srcs = [
        "platformdesc.go",
        "platformdesc_amd64.go",
    ],
    visibility = [
        "//pkg/sentry:internal",
        "//sandboxexec/sandbox:__pkg__",
    ],
    deps = [
        "//pkg/fd",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
