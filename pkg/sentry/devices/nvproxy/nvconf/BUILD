load("//tools:defs.bzl", "go_library", "go_test")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "nvconf",
    srcs = [
        "caps.go",
        "hostsettings.go",
        "nvconf.go",
        "version.go",
    ],
    visibility = [
        "//pkg/sentry:internal",
        "//tools:__subpackages__",
    ],
    deps = [
        "//pkg/log",
    ],
)

go_test(
    name = "nvconf_test",
    size = "small",
    srcs = ["caps_test.go"],
    library = ":nvconf",
)
