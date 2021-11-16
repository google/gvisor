load("//tools:defs.bzl", "go_library", "go_test")
load("//tools:deps.bzl", "deps_test")

package(licenses = ["notice"])

exports_files(["LICENSE"])

go_library(
    name = "gvunix",
    srcs = [
        "gvunix.go",
        "sigaction_darwin_unsafe.go",
        "syscall_darwin_libSystem_unsafe.go",
        "syscalls_darwin_arm64.s",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

# gvunix shouldn't depend on much: just the stateify deps and unix package.
deps_test(
    name = "gvunix_deps_test",
    allowed = [
        "//pkg/gohacks",
        "//pkg/goid",
        "//pkg/linewriter",
        "//pkg/log",
        "//pkg/state",
        "//pkg/state/wire",
        "//pkg/sync",
        "@org_golang_x_sys//unix:go_default_library",
    ],
    allowed_prefixes = [
        "@org_golang_x_sys//internal/unsafeheader",
    ],
    targets = [":gvunix"],
)

go_test(
    name = "gvunix_test",
    srcs = [
        "gvunix_stub_test.go",
        "sigaction_darwin_test.go",
    ],
    library = ":gvunix",
    deps = [
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
