load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],  # Apache 2.0
)

# buildifier: disable=platform-specific-binaries
go_library(
    name = "slimvm",
    srcs = [
        "address_space.go",
        "address_space_x86.go",
        "allocator.go",
        "bluepill.go",
        "bluepill_amd64.go",
        "bluepill_amd64.s",
        "bluepill_amd64_unsafe.go",
        "bluepill_fault.go",
        "bluepill_unsafe.go",
        "context.go",
        "filters_amd64.go",
        "machine.go",
        "machine_amd64.go",
        "machine_amd64_unsafe.go",
        "machine_unsafe.go",
        "pcids_x86.go",
        "physical_map.go",
        "physical_map_amd64.go",
        "slimvm.go",
        "slimvm_amd64.go",
        "slimvm_amd64_unsafe.go",
        "slimvm_const.go",
        "slimvm_const_amd64.go",
    ],
    # TODO: b/529809802 - Enable nogo.
    nogo = False,
    target_compatible_with = [
        "@platforms//cpu:x86_64",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/bitmap",
        "//pkg/context",
        "//pkg/cpuid",
        "//pkg/fd",
        "//pkg/hostarch",
        "//pkg/hostsyscall",
        "//pkg/hosttid",
        "//pkg/log",
        "//pkg/ring0",
        "//pkg/ring0/pagetables",
        "//pkg/seccomp",
        "//pkg/sentry/arch",
        "//pkg/sentry/arch/fpu",
        "//pkg/sentry/hostmm",
        "//pkg/sentry/memmap",
        "//pkg/sentry/platform",
        "//pkg/sentry/platform/interrupt",
        "//pkg/sighandling",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

# buildifier: disable=platform-specific-binaries
go_test(
    name = "slimvm_test",
    srcs = [
        "slimvm_test.go",
    ],
    library = ":slimvm",
    # TODO: b/529809802 - Enable nogo.
    nogo = False,
    tags = [
        "manual",
        "nogotsan",
        "noguitar",
        "notap",
        "requires-slimvm",
    ],
    target_compatible_with = [
        "@platforms//cpu:x86_64",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/cpuid",
        "//pkg/hostarch",
        "//pkg/ring0",
        "//pkg/ring0/pagetables",
        "//pkg/sentry/arch",
        "//pkg/sentry/arch/fpu",
        "//pkg/sentry/platform",
        "//pkg/sentry/platform/slimvm/testutil",
        "//pkg/sentry/time",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
