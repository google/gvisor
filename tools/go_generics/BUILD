load("@io_bazel_rules_go//go:def.bzl", "go_binary")

package(licenses = ["notice"])

go_binary(
    name = "go_generics",
    srcs = [
        "generics.go",
        "imports.go",
        "remove.go",
    ],
    visibility = ["//visibility:public"],
    deps = ["//tools/go_generics/globals"],
)

genrule(
    name = "go_generics_tests",
    srcs = glob(["generics_tests/**"]) + [":go_generics"],
    outs = ["go_generics_tests.tgz"],
    cmd = "tar -czvhf $@ $(SRCS)",
)

genrule(
    name = "go_generics_test_bundle",
    srcs = [
        ":go_generics_tests.tgz",
        ":go_generics_unittest.sh",
    ],
    outs = ["go_generics_test.sh"],
    cmd = "cat $(location :go_generics_unittest.sh) $(location :go_generics_tests.tgz) > $@",
    executable = True,
)

sh_test(
    name = "go_generics_test",
    size = "small",
    srcs = ["go_generics_test.sh"],
)
