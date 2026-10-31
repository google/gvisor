load("//runsc:sidecar.bzl", "freestanding_sidecar")
load("//tools:defs.bzl", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

# gvisor-proc-umounter must remain a statically-linked, freestanding (no libc)
# C binary that fits in a single 4KiB page. Read its comments as to why.
freestanding_sidecar(
    name = "procumounter_binary",
    src = "procumounter.c",
    out = "gvisor-proc-umounter",
)

go_test(
    name = "procumounter_test",
    size = "small",
    srcs = ["procumounter_test.go"],
    data = [":procumounter_binary"],
    deps = [
        "//pkg/test/testutil",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
