load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "licensecheck",
    srcs = ["licensecheck.go"],
    marshal = False,
    stateify = False,
    visibility = ["//tools/licensecheck:__subpackages__"],
    deps = [
        "@in_gopkg_yaml_v3//:go_default_library",
        "@org_golang_x_mod//modfile:go_default_library",
        "@org_golang_x_mod//module:go_default_library",
        "@org_golang_x_mod//semver:go_default_library",
    ],
)

go_test(
    name = "licensecheck_test",
    size = "small",
    srcs = ["licensecheck_test.go"],
    data = [
        "dependencies.yaml",
        "//governance:licensing.yaml",
    ],
    library = ":licensecheck",
)
