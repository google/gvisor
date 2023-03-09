load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "victim",
    testonly = 1,
    srcs = [
        "seccomp_test_victim.go",
        "seccomp_test_victim_amd64.go",
        "seccomp_test_victim_arm64.go",
    ],
    nogo = False,
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/seccomp",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
