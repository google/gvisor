load("//tools:arch.bzl", "arch_genrule", "select_arch")
load("//tools:defs.bzl", "go_library")
load("//tools/nogo:defs.bzl", "nogo_facts")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

nogo_facts(
    name = "stub_impl",
    srcs = [
        "stub_defs.go",
        "syscall_thread_defs.go",
    ],
    output = "stub_impl.s",
    template = select_arch(
        amd64 = "stub_amd64.s",
        arm64 = "stub_arm64.s",
    ),
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/hostarch",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

arch_genrule(
    name = "stub_impl_arch",
    src = ":stub_impl",
    template = "stub_impl_%s.s",
)

go_template_instance(
    name = "subprocess_list",
    out = "subprocess_list.go",
    package = "systrap",
    prefix = "subprocess",
    template = "//pkg/ilist:generic_list",
    types = {
        "Linker": "*subprocess",
        "Element": "*subprocess",
    },
)

go_library(
    name = "systrap",
    srcs = [
        "filters.go",
        "filters_amd64.go",
        "filters_arm64.go",
        "lib_amd64.s",
        "lib_arm64.s",
        "stub_defs.go",
        "stub_unsafe.go",
        "subprocess.go",
        "subprocess_amd64.go",
        "subprocess_amd64_unsafe.go",
        "subprocess_arm64.go",
        "subprocess_arm64_unsafe.go",
        "subprocess_linux.go",
        "subprocess_linux_unsafe.go",
        "subprocess_list.go",
        "subprocess_pool.go",
        "subprocess_unsafe.go",
        "syscall_thread.go",
        "syscall_thread_amd64.go",
        "syscall_thread_arm64.go",
        "syscall_thread_defs.go",
        "syscall_thread_unsafe.go",
        "sysmsg_thread.go",
        "sysmsg_thread_amd64.go",
        "sysmsg_thread_arm64.go",
        "sysmsg_thread_unsafe.go",
        "systrap.go",
        "systrap_amd64.go",
        "systrap_arm64.go",
        "systrap_arm64_unsafe.go",
        "systrap_unsafe.go",
        ":stub_impl_arch",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/context",
        "//pkg/cpuid",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/memutil",
        "//pkg/pool",
        "//pkg/safecopy",
        "//pkg/seccomp",
        "//pkg/sentry/arch",
        "//pkg/sentry/memmap",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/platform",
        "//pkg/sentry/platform/interrupt",
        "//pkg/sentry/platform/systrap/sysmsg",
        "//pkg/sentry/platform/systrap/usertrap",
        "//pkg/sentry/usage",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
