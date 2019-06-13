load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "server",
    srcs = ["server.go"],
    importpath = "gvisor.dev/gvisor/pkg/control/server",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//pkg/unet",
        "//pkg/urpc",
    ],
)
