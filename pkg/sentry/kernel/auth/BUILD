package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "auth_state",
    srcs = [
        "credentials.go",
        "id.go",
        "id_map_range.go",
        "id_map_set.go",
        "user_namespace.go",
    ],
    out = "auth_state.go",
    package = "auth",
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

go_library(
    name = "auth",
    srcs = [
        "auth.go",
        "auth_state.go",
        "capability_set.go",
        "context.go",
        "credentials.go",
        "id.go",
        "id_map.go",
        "id_map_functions.go",
        "id_map_range.go",
        "id_map_set.go",
        "user_namespace.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/bits",
        "//pkg/log",
        "//pkg/sentry/context",
        "//pkg/state",
        "//pkg/syserror",
    ],
)
