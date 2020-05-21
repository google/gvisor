load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "file_refcount_set",
    out = "file_refcount_set.go",
    imports = {
        "platform": "gvisor.dev/gvisor/pkg/sentry/platform",
    },
    package = "mm",
    prefix = "fileRefcount",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "uint64",
        "Range": "platform.FileRange",
        "Value": "int32",
        "Functions": "fileRefcountSetFunctions",
    },
)

go_template_instance(
    name = "vma_set",
    out = "vma_set.go",
    consts = {
        "minDegree": "8",
        "trackGaps": "1",
    },
    imports = {
        "usermem": "gvisor.dev/gvisor/pkg/usermem",
    },
    package = "mm",
    prefix = "vma",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "usermem.Addr",
        "Range": "usermem.AddrRange",
        "Value": "vma",
        "Functions": "vmaSetFunctions",
    },
)

go_template_instance(
    name = "pma_set",
    out = "pma_set.go",
    consts = {
        "minDegree": "8",
    },
    imports = {
        "usermem": "gvisor.dev/gvisor/pkg/usermem",
    },
    package = "mm",
    prefix = "pma",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "usermem.Addr",
        "Range": "usermem.AddrRange",
        "Value": "pma",
        "Functions": "pmaSetFunctions",
    },
)

go_template_instance(
    name = "io_list",
    out = "io_list.go",
    package = "mm",
    prefix = "io",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*ioResult",
        "Linker": "*ioResult",
    },
)

go_library(
    name = "mm",
    srcs = [
        "address_space.go",
        "aio_context.go",
        "aio_context_state.go",
        "debug.go",
        "file_refcount_set.go",
        "io.go",
        "io_list.go",
        "lifecycle.go",
        "metadata.go",
        "mm.go",
        "pma.go",
        "pma_set.go",
        "procfs.go",
        "save_restore.go",
        "shm.go",
        "special_mappable.go",
        "syscalls.go",
        "vma.go",
        "vma_set.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/context",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/safecopy",
        "//pkg/safemem",
        "//pkg/sentry/arch",
        "//pkg/sentry/fs/proc/seqfile",
        "//pkg/sentry/fsbridge",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/futex",
        "//pkg/sentry/kernel/shm",
        "//pkg/sentry/limits",
        "//pkg/sentry/memmap",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/platform",
        "//pkg/sentry/usage",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/tcpip/buffer",
        "//pkg/usermem",
    ],
)

go_test(
    name = "mm_test",
    size = "small",
    srcs = ["mm_test.go"],
    library = ":mm",
    deps = [
        "//pkg/context",
        "//pkg/sentry/arch",
        "//pkg/sentry/contexttest",
        "//pkg/sentry/limits",
        "//pkg/sentry/memmap",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/platform",
        "//pkg/syserror",
        "//pkg/usermem",
    ],
)
