load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "reviver",
    srcs = [
        "github.go",
        "reviver.go",
    ],
    nogo = False,
    visibility = [
        "//tools/github:__subpackages__",
    ],
    deps = ["@com_github_google_go_github_v42//github:go_default_library"],
)

go_test(
    name = "reviver_test",
    size = "small",
    srcs = [
        "github_test.go",
        "reviver_test.go",
    ],
    library = ":reviver",
    nogo = False,
)
