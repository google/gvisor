load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "file_refcount_set",
    out = "file_refcount_set.go",
    imports = {
        "memmap": "gvisor.dev/gvisor/pkg/sentry/memmap",
    },
    package = "mm",
    prefix = "fileRefcount",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "uint64",
        "Range": "memmap.FileRange",
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

go_template_instance(
    name = "aio_mappable_refs",
    out = "aio_mappable_refs.go",
    package = "mm",
    prefix = "aioMappable",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "aioMappable",
    },
)

go_template_instance(
    name = "special_mappable_refs",
    out = "special_mappable_refs.go",
    package = "mm",
    prefix = "SpecialMappable",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "SpecialMappable",
    },
)

go_library(
    name = "mm",
    srcs = [
        "address_space.go",
        "aio_context.go",
        "aio_context_state.go",
        "aio_mappable_refs.go",
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
        "special_mappable_refs.go",
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
        "//pkg/refsvfs2",
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
        "//pkg/sentry/securityhooks",
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
