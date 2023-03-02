load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
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
        "runtime.go",
        "runtime_amd64.go",
        "runtime_constants.go",
        "runtime_other.go",
        "runtime_spinning_amd64.s",
        "runtime_spinning_other.s",
        "runtime_unsafe.go",
        "rwmutex_unsafe.go",
        "seqcount.go",
        "sync.go",
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
