load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "client",
    srcs = [
        "client.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/control/client",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/unet",
        "//pkg/urpc",
    ],
)
