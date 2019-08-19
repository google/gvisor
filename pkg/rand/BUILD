load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "rand",
    srcs = [
        "rand.go",
        "rand_linux.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/rand",
    visibility = ["//:sandbox"],
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)
