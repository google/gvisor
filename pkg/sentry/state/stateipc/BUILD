load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_template_instance(
    name = "asyncfileclient_refs",
    out = "asyncfileclient_refs.go",
    package = "stateipc",
    prefix = "asyncFileClient",
    template = "//pkg/refs:refs_template",
    types = {
        "T": "AsyncFileClient",
    },
)

go_template_instance(
    name = "destinationfile_atomicptrmap",
    out = "destinationfile_atomicptrmap_unsafe.go",
    package = "stateipc",
    prefix = "destinationFile",
    template = "//pkg/sync/atomicptrmap:generic_atomicptrmap",
    types = {
        "Key": "uint32",
        "Value": "destinationFile",
        "Hasher": "clientFileHandleHasher",
    },
)

go_template_instance(
    name = "sourcefile_atomicptrmap",
    out = "sourcefile_atomicptrmap_unsafe.go",
    package = "stateipc",
    prefix = "sourceFile",
    template = "//pkg/sync/atomicptrmap:generic_atomicptrmap",
    types = {
        "Key": "uint32",
        "Value": "sourceFile",
        "Hasher": "clientFileHandleHasher",
    },
)

go_library(
    name = "stateipc",
    srcs = [
        "asyncfileclient_refs.go",
        "client.go",
        "common.go",
        "common_unsafe.go",
        "destinationfile_atomicptrmap_unsafe.go",
        "server.go",
        "sourcefile_atomicptrmap_unsafe.go",
        "stateipc.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/cleanup",
        "//pkg/eventfd",
        "//pkg/flipcall",
        "//pkg/gohacks",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/sentry/memmap",
        "//pkg/sentry/state/stateio",
        "//pkg/sync",
        "//pkg/urpc",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "stateipc_test",
    size = "small",
    srcs = [
        "stateipc_test.go",
    ],
    library = ":stateipc",
    deps = [
        "//pkg/rand",
        "//pkg/sentry/memmap",
        "//pkg/sentry/state/stateio",
        "//pkg/unet",
        "//pkg/urpc",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
