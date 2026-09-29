load("@rules_python//python:defs.bzl", "py_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

py_test(
    name = "clang_tidy_test",
    size = "small",
    srcs = ["clang_tidy_test.py"],
    args = ["$(rootpath clang_tidy.py)"],
    data = ["clang_tidy.py"],
)
