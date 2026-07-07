# Placeholder: load py_library
# Placeholder: load py_test
load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "sandbox",
    srcs = [
        "oci.go",
        "sandbox.go",
    ],
    visibility = ["//:__subpackages__"],
    deps = ["@com_github_opencontainers_runtime_spec//specs-go:go_default_library"],
)

go_test(
    name = "sandbox_test",
    srcs = [
        "oci_test.go",
        "sandbox_test.go",
    ],
    data = ["//runsc"],
    tags = ["nogotsan"],
    deps = [
        ":sandbox",
        "//pkg/test/testutil",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
    ],
)

py_library(
    name = "sandbox_py",
    srcs = ["sandbox.py"],
    visibility = ["//:__subpackages__"],
)

py_test(
    name = "sandbox_py_test",
    srcs = ["sandbox_test.py"],
    data = ["//runsc"],
    main = "sandbox_test.py",
    tags = ["nogotsan"],
    deps = [
        ":sandbox_py",
    ],
)
