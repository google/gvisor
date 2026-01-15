load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_template_instance(
    name = "deferred_list",
    out = "deferred_list.go",
    package = "state",
    prefix = "deferred",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*objectEncodeState",
        "Linker": "*objectEncodeState",
    },
)

go_template_instance(
    name = "ods_list",
    out = "ods_list.go",
    package = "state",
    prefix = "ods",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*odsListElem",
        "Linker": "*odsListElem",
    },
)

go_template_instance(
    name = "addr_range",
    out = "addr_range.go",
    package = "state",
    prefix = "addr",
    template = "//pkg/segment:generic_range",
    types = {
        "T": "uintptr",
    },
)

go_template_instance(
    name = "addr_set",
    out = "addr_set.go",
    consts = {
        "minDegree": "10",
    },
    imports = {
        "reflect": "reflect",
    },
    package = "state",
    prefix = "addr",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "uintptr",
        "Range": "addrRange",
        "Value": "*objectEncodeState",
        "Functions": "addrSetFunctions",
    },
)

go_library(
    name = "state",
    srcs = [
        "addr_range.go",
        "addr_set.go",
        "decode.go",
        "decode_unsafe.go",
        "deferred_list.go",
        "encode.go",
        "encode_unsafe.go",
        "ods_list.go",
        "state.go",
        "state_norace.go",
        "state_race.go",
        "stats.go",
        "types.go",
    ],
    marshal = False,
    stateify = False,
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//pkg/state/wire",
    ],
)
