package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

go_template_instance(
    name = "host_map_set",
    out = "host_map_set.go",
    consts = {
        "minDegree": "15",
    },
    imports = {
        "usermem": "gvisor.googlesource.com/gvisor/pkg/sentry/usermem",
    },
    package = "kvm",
    prefix = "hostMap",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "usermem.Addr",
        "Range": "usermem.AddrRange",
        "Value": "uintptr",
        "Functions": "hostMapSetFunctions",
    },
)

go_library(
    name = "kvm",
    srcs = [
        "address_space.go",
        "bluepill.go",
        "bluepill_amd64.go",
        "bluepill_amd64.s",
        "bluepill_amd64_unsafe.go",
        "bluepill_fault.go",
        "bluepill_unsafe.go",
        "context.go",
        "host_map.go",
        "host_map_set.go",
        "kvm.go",
        "kvm_amd64.go",
        "kvm_amd64_unsafe.go",
        "kvm_const.go",
        "machine.go",
        "machine_amd64.go",
        "machine_amd64_unsafe.go",
        "machine_unsafe.go",
        "physical_map.go",
        "virtual_map.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/platform/kvm",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/cpuid",
        "//pkg/log",
        "//pkg/sentry/arch",
        "//pkg/sentry/platform",
        "//pkg/sentry/platform/filemem",
        "//pkg/sentry/platform/interrupt",
        "//pkg/sentry/platform/procid",
        "//pkg/sentry/platform/ring0",
        "//pkg/sentry/platform/ring0/pagetables",
        "//pkg/sentry/platform/safecopy",
        "//pkg/sentry/time",
        "//pkg/sentry/usermem",
    ],
)

go_test(
    name = "kvm_test",
    size = "small",
    srcs = [
        "kvm_test.go",
        "virtual_map_test.go",
    ],
    embed = [":kvm"],
    tags = [
        "nogotsan",
        "requires-kvm",
    ],
    deps = [
        "//pkg/sentry/arch",
        "//pkg/sentry/platform",
        "//pkg/sentry/platform/kvm/testutil",
        "//pkg/sentry/platform/ring0",
        "//pkg/sentry/platform/ring0/pagetables",
        "//pkg/sentry/usermem",
    ],
)
