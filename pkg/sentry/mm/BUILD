load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//pkg/sync/locking:locking.bzl", "declare_mutex", "declare_rwmutex")

package(licenses = ["notice"])

declare_mutex(
    name = "aio_context_mutex",
    out = "aio_context_mutex.go",
    package = "mm",
    prefix = "aioContext",
)

declare_mutex(
    name = "aio_manager_mutex",
    out = "aio_manager_mutex.go",
    package = "mm",
    prefix = "aioManager",
)

declare_rwmutex(
    name = "mapping_mutex",
    out = "mapping_mutex.go",
    package = "mm",
    prefix = "mapping",
)

declare_rwmutex(
    name = "active_mutex",
    out = "active_mutex.go",
    nested_lock_names = ["forked"],
    package = "mm",
    prefix = "active",
)

declare_mutex(
    name = "metadata_mutex",
    out = "metadata_mutex.go",
    package = "mm",
    prefix = "metadata",
)

declare_mutex(
    name = "private_refs_mutex",
    out = "private_refs_mutex.go",
    package = "mm",
    prefix = "privateRefs",
)

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
        "hostarch": "gvisor.dev/gvisor/pkg/hostarch",
    },
    package = "mm",
    prefix = "vma",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "hostarch.Addr",
        "Range": "hostarch.AddrRange",
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
        "hostarch": "gvisor.dev/gvisor/pkg/hostarch",
    },
    package = "mm",
    prefix = "pma",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "hostarch.Addr",
        "Range": "hostarch.AddrRange",
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
    template = "//pkg/refs:refs_template",
    types = {
        "T": "aioMappable",
    },
)

go_template_instance(
    name = "special_mappable_refs",
    out = "special_mappable_refs.go",
    package = "mm",
    prefix = "SpecialMappable",
    template = "//pkg/refs:refs_template",
    types = {
        "T": "SpecialMappable",
    },
)

go_library(
    name = "mm",
    srcs = [
        "active_mutex.go",
        "address_space.go",
        "aio_context.go",
        "aio_context_mutex.go",
        "aio_context_state.go",
        "aio_manager_mutex.go",
        "aio_mappable_refs.go",
        "debug.go",
        "file_refcount_set.go",
        "io.go",
        "io_list.go",
        "lifecycle.go",
        "mapping_mutex.go",
        "metadata.go",
        "metadata_mutex.go",
        "mm.go",
        "pma.go",
        "pma_set.go",
        "private_refs_mutex.go",
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
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/safecopy",
        "//pkg/safemem",
        "//pkg/sentry/arch",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/futex",
        "//pkg/sentry/kernel/shm",
        "//pkg/sentry/limits",
        "//pkg/sentry/memmap",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/platform",
        "//pkg/sentry/usage",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/sync/locking",
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
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/sentry/arch",
        "//pkg/sentry/contexttest",
        "//pkg/sentry/limits",
        "//pkg/sentry/memmap",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/platform",
        "//pkg/usermem",
    ],
)
