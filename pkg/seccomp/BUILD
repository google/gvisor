load("//tools:defs.bzl", "go_binary", "go_embed_data", "go_library", "go_test")

package(licenses = ["notice"])

go_binary(
    name = "victim",
    testonly = 1,
    srcs = [
        "seccomp_test_victim.go",
        "seccomp_test_victim_amd64.go",
        "seccomp_test_victim_arm64.go",
    ],
    nogo = False,
    deps = [
        ":seccomp",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_embed_data(
    name = "victim_data",
    testonly = 1,
    src = "victim",
    package = "seccomp",
    var = "victimData",
)

go_library(
    name = "seccomp",
    srcs = [
        "seccomp.go",
        "seccomp_amd64.go",
        "seccomp_arm64.go",
        "seccomp_rules.go",
        "seccomp_unsafe.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/bpf",
        "//pkg/log",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "seccomp_test",
    size = "small",
    srcs = [
        "seccomp_test.go",
        ":victim_data",
    ],
    library = ":seccomp",
    deps = [
        "//pkg/abi/linux",
        "//pkg/bpf",
        "//pkg/hostarch",
    ],
)
