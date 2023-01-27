load("//tools:defs.bzl", "arch_genrule", "go_library", "go_test", "select_arch")
load("//tools/nogo:defs.bzl", "nogo_facts")

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

nogo_facts(
    name = "runtime_spinning_impl",
    srcs = ["runtime.go"],
    output = "runtime_spinning_impl.s",
    template = select_arch(
        amd64 = "runtime_spinning_amd64.s",
        arm64 = "runtime_spinning_other.s",
    ),
)

# For arm64 (or any !amd64), this will generate runtime_spinning_impl_arm64.s,
# which is a copy of the (empty) runtime_spinning_other.s.
#
# On the go branch, only amd64 and arm64 will have have files, other arches
# won't select any of these files. That is fine because the contents only
# matter for amd64 anyway.
arch_genrule(
    name = "runtime_spinning_impl_arch",
    src = ":runtime_spinning_impl",
    template = "runtime_spinning_impl_%s.s",
)

# Architecture-independent constants.
nogo_facts(
    name = "runtime_constants_impl",
    srcs = ["runtime.go"],
    output = "runtime_constants_impl.go",
    template = "runtime_constants.tmpl",
)

go_library(
    name = "sync",
    srcs = [
        "aliases.go",
        "checklocks_off_unsafe.go",
        "checklocks_on_unsafe.go",
        "gate_unsafe.go",
        "goyield_go113_unsafe.go",
        "goyield_unsafe.go",
        "mutex_unsafe.go",
        "nocopy.go",
        "norace_unsafe.go",
        "race_amd64.s",
        "race_arm64.s",
        "race_unsafe.go",
        "runtime_amd64.go",
        "runtime_other.go",
        "runtime_unsafe.go",
        "rwmutex_unsafe.go",
        "seqcount.go",
        "sync.go",
        ":runtime_constants_impl",
        ":runtime_spinning_impl_arch",
    ],
    marshal = False,
    stateify = False,
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/gohacks",
        "//pkg/goid",
    ],
)

go_test(
    name = "sync_test",
    size = "small",
    srcs = [
        "gate_test.go",
        "rwmutex_test.go",
        "seqcount_test.go",
    ],
    library = ":sync",
)
