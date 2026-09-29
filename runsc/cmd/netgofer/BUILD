load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

filegroup(
    name = "go_export_sources",
    srcs = glob(
        ["*.go"],
        exclude = ["*_test.go"],
    ),
    visibility = ["//:__pkg__"],
)

go_binary(
    name = "runsc-netgofer",
    srcs = [
        "main.go",
    ],
    noasan = True,
    pure = True,
    visibility = [
        "//:sandbox",
    ],
    x_defs = {"gvisor.dev/gvisor/runsc/version.version": "{STABLE_VERSION}"},
    deps = [
        "//runsc/cli",
        "//runsc/cmd/util",
        "//runsc/gofer/net",
        "//runsc/gvisorbinaries",
    ],
)
