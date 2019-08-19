load("//tools:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_test")

package(licenses = ["notice"])

alias(
    name = "mockgen",
    actual = "@com_github_golang_mock//mockgen:mockgen",
)

MOCK_SRC_PACKAGE = "gvisor.dev/gvisor/pkg/p9"

# mockgen_reflect is a source file that contains mock generation code that
# imports the p9 package and generates a specification via reflection. The
# usual generation path must be split into two distinct parts because the full
# source tree is not available to all build targets. Only declared depencies
# are available (and even then, not the Go source files).
genrule(
    name = "mockgen_reflect",
    testonly = 1,
    outs = ["mockgen_reflect.go"],
    cmd = (
        "$(location :mockgen) " +
        "-package p9test " +
        "-prog_only " + MOCK_SRC_PACKAGE + " " +
        "Attacher,File > $@"
    ),
    tools = [":mockgen"],
)

# mockgen_exec is the binary that includes the above reflection generator.
# Running this binary will emit an encoded version of the p9 Attacher and File
# structures. This is consumed by the mocks genrule, below.
go_binary(
    name = "mockgen_exec",
    testonly = 1,
    srcs = ["mockgen_reflect.go"],
    deps = [
        "//pkg/p9",
        "@com_github_golang_mock//mockgen/model:go_default_library",
    ],
)

# mocks consumes the encoded output above, and generates the full source for a
# set of mocks. These are included directly in the p9test library.
genrule(
    name = "mocks",
    testonly = 1,
    outs = ["mocks.go"],
    cmd = (
        "$(location :mockgen) " +
        "-package p9test " +
        "-exec_only $(location :mockgen_exec) " + MOCK_SRC_PACKAGE + " File > $@"
    ),
    tools = [
        ":mockgen",
        ":mockgen_exec",
    ],
)

go_library(
    name = "p9test",
    srcs = [
        "mocks.go",
        "p9test.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/p9/p9test",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/fd",
        "//pkg/log",
        "//pkg/p9",
        "//pkg/unet",
        "@com_github_golang_mock//gomock:go_default_library",
    ],
)

go_test(
    name = "client_test",
    size = "small",
    srcs = ["client_test.go"],
    embed = [":p9test"],
    deps = [
        "//pkg/fd",
        "//pkg/p9",
        "@com_github_golang_mock//gomock:go_default_library",
    ],
)
