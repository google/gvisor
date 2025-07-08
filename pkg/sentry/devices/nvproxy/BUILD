load("//pkg/sync/locking:locking.bzl", "declare_mutex")
load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

declare_mutex(
    name = "fds_mutex",
    out = "fds_mutex.go",
    package = "nvproxy",
    prefix = "fds",
)

declare_mutex(
    name = "frontend_mmap_mutex",
    out = "frontend_mmap_mutex.go",
    package = "nvproxy",
    prefix = "frontendMmap",
)

declare_mutex(
    name = "objs_mutex",
    out = "objs_mutex.go",
    package = "nvproxy",
    prefix = "objs",
)

go_template_instance(
    name = "object_free_list",
    out = "object_free_list.go",
    package = "nvproxy",
    prefix = "objectFree",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*object",
        "Linker": "*object",
    },
)

go_library(
    name = "nvproxy",
    srcs = [
        "fds_mutex.go",
        "frontend.go",
        "frontend_mmap.go",
        "frontend_mmap_mutex.go",
        "frontend_mmap_unsafe.go",
        "frontend_unsafe.go",
        "handlers.go",
        "nvproxy.go",
        "nvproxy_unsafe.go",
        "object.go",
        "object_free_list.go",
        "objs_mutex.go",
        "save_restore.go",
        "save_restore_impl.go",
        "seccomp_filters.go",
        "uvm.go",
        "uvm_mmap.go",
        "uvm_unsafe.go",
        "version.go",
    ],
    visibility = [
        "//pkg/sentry:internal",
        "//test/gpu:__subpackages__",
        "//tools:__subpackages__",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/abi/nvgpu",
        "//pkg/atomicbitops",
        "//pkg/cleanup",
        "//pkg/context",
        "//pkg/devutil",
        "//pkg/errors/linuxerr",
        "//pkg/fdnotifier",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/marshal",
        "//pkg/marshal/primitive",
        "//pkg/safemem",
        "//pkg/seccomp",
        "//pkg/sentry/arch",
        "//pkg/sentry/devices/nvproxy/nvconf",
        "//pkg/sentry/fsutil",
        "//pkg/sentry/kernel",
        "//pkg/sentry/memmap",
        "//pkg/sentry/mm",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/sync/locking",
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "nvproxy_test",
    srcs = ["nvproxy_test.go"],
    library = ":nvproxy",
    deps = [
        "//pkg/abi/nvgpu",
        "//pkg/seccomp",
        "//pkg/sentry/devices/nvproxy/nvconf",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "nvproxy_driver_parity_test",
    srcs = ["nvproxy_driver_parity_test.go"],
    data = ["//tools/nvidia_driver_differ:driver_ast_parser"],
    deps = [
        ":nvproxy",
        "//pkg/abi/nvgpu",
        "//pkg/sentry/devices/nvproxy/nvconf",
        "//pkg/test/testutil",
        "//tools/gpu/drivers",
        "//tools/nvidia_driver_differ/parser",
    ],
)
