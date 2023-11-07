load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "rand",
    srcs = [
        "rand.go",
        "rand_linux.go",
        "rng.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/sync",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "rand_test",
    srcs = ["rng_test.go"],
    library = ":rand",
)
