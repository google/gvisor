load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "hostos",
    srcs = ["hostos.go"],
    visibility = ["//:sandbox"],
    deps = [
        "@org_golang_x_mod//semver:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "hostos_test",
    srcs = ["hostos_test.go"],
    library = ":hostos",
)
