load("//pkg/sync/locking:locking.bzl", "declare_mutex", "declare_rwmutex")
load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_template_instance(
    name = "atomicptr_credentials",
    out = "atomicptr_credentials_unsafe.go",
    package = "auth",
    suffix = "Credentials",
    template = "//pkg/sync/atomicptr:generic_atomicptr",
    types = {
        "Value": "Credentials",
    },
)

go_template_instance(
    name = "id_map_range",
    out = "id_map_range.go",
    package = "auth",
    prefix = "idMap",
    template = "//pkg/segment:generic_range",
    types = {
        "T": "uint32",
    },
)

go_template_instance(
    name = "id_map_set",
    out = "id_map_set.go",
    consts = {
        "minDegree": "3",
    },
    package = "auth",
    prefix = "idMap",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "uint32",
        "Range": "idMapRange",
        "Value": "uint32",
        "Functions": "idMapFunctions",
    },
)

declare_mutex(
    name = "user_namespace_mutex",
    out = "user_namespace_mutex.go",
    nested_lock_names = ["ns"],
    package = "auth",
    prefix = "userNamespace",
)

declare_rwmutex(
    name = "keyset_mutex",
    out = "keyset_mutex.go",
    package = "auth",
    prefix = "keyset",
)

declare_mutex(
    name = "keyset_transaction_mutex",
    out = "keyset_transaction_mutex.go",
    package = "auth",
    prefix = "keysetTransaction",
)

go_library(
    name = "auth",
    srcs = [
        "atomicptr_credentials_unsafe.go",
        "auth.go",
        "capability_set.go",
        "context.go",
        "credentials.go",
        "id.go",
        "id_map.go",
        "id_map_functions.go",
        "id_map_range.go",
        "id_map_set.go",
        "key.go",
        "keyset_mutex.go",
        "keyset_transaction_mutex.go",
        "user_namespace.go",
        "user_namespace_mutex.go",
    ],
    marshal = True,
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/bits",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/log",
        "//pkg/rand",
        "//pkg/sentry/seccheck",
        "//pkg/sentry/seccheck/points:points_go_proto",
        "//pkg/sync",
        "//pkg/sync/locking",
    ],
)

go_test(
    name = "auth_test",
    srcs = ["capability_set_test.go"],
    library = ":auth",
    deps = [
        "//pkg/abi/linux",
        "//pkg/errors/linuxerr",
    ],
)
