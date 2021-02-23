load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "securityhooks",
    srcs = [
        "securityhooks.go",
    ],
    imports = [
    ],
    marshal = True,
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/context",
        "//pkg/sentry/fsbridge",
        "//pkg/sentry/memmap",
        "//pkg/usermem",
    ],
)
