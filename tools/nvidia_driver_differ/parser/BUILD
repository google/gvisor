load("@rules_pkg//pkg:mappings.bzl", "pkg_files", "strip_prefix")
load("@rules_pkg//pkg:zip.bzl", "pkg_zip")
load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

pkg_files(
    name = "builtin_header_files",
    srcs = ["@llvm-project//clang:builtin_headers_gen"],
    strip_prefix = strip_prefix.from_root("clang/staging"),
)

# Keep the headers with the parser's LLVM source, including when run_differ
# extracts the parser executable outside the Bazel runfiles tree.
# Keep CLANG-LICENSE.TXT byte-identical to clang/LICENSE.TXT in the LLVM
# source archive selected by MODULE.bazel.
pkg_zip(
    name = "builtin_headers",
    srcs = [
        "CLANG-LICENSE.TXT",
        ":builtin_header_files",
    ],
    out = "builtin_headers.zip",
    package_dir = "",
    strip_prefix = ".",
    visibility = ["//tools/nvidia_driver_differ:__pkg__"],
)

go_library(
    name = "parser",
    srcs = [
        "auxiliary_files.go",
        "clang_config.go",
        "json_definitions.go",
        "runner.go",
        "sources.go",
    ],
    embedsrcs = ["builtin_headers.zip"],
    importpath = "gvisor.dev/gvisor/tools/nvidia_driver_differ/parser",
    visibility = [
        "//pkg/sentry/devices/nvproxy:__subpackages__",
        "//tools/nvidia_driver_differ:__subpackages__",
    ],
    deps = [
        "//pkg/sentry/devices/nvproxy",
        "//pkg/sentry/devices/nvproxy/nvconf",
        "//pkg/zip",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)
