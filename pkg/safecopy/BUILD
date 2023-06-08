load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "safecopy",
    srcs = [
        "atomic_amd64.s",
        "atomic_arm64.s",
        "memclr_amd64.s",
        "memclr_arm64.s",
        "memcpy_amd64.s",
        "memcpy_arm64.s",
        "safecopy.go",
        "safecopy_amd64_unsafe.go",
        "safecopy_arm64.go",
        "safecopy_unsafe.go",
        "sighandler_amd64.s",
        "sighandler_arm64.s",
        "xrstor_amd64.s",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/errors",
        "//pkg/errors/linuxerr",
        "//pkg/sighandling",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "safecopy_test",
    srcs = [
        "safecopy_test.go",
    ],
    library = ":safecopy",
    deps = [
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "safecopy_x_test",
    srcs = [
        "safecopy_amd64_test.go",
        "safecopy_arm64_test.go",
    ],
    # NOTE: It seems that bazel code generation does not properly parse tags
    # when run via the architecture transition for nogo. This should be fixed
    # at some point in the future, but for now we can simply skip nogo analysis
    # on the test itself. It still applies to the core library.
    nogo = False,
    tags = ["not_run:arm"],
    deps = [
        "//pkg/cpuid",
        "//pkg/safecopy",
        "//pkg/sentry/arch/fpu",
    ],
)
