load("//runsc:sidecar.bzl", "freestanding_sidecar")
load("//tools:defs.bzl", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

# runsc-fd-parking must remain a statically-linked, freestanding
# (no libc) C binary. It exists for the lifetime of each sandbox just to hold
# some FDs, so its runtime memory footprint *must* stay absolutely minimal.
freestanding_sidecar(
    name = "fdparking_binary",
    src = "fdparking.c",
    out = "runsc-fd-parking",
)

go_test(
    name = "fdparking_test",
    size = "small",
    srcs = ["fdparking_test.go"],
    data = [":fdparking_binary"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/test/testutil",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
