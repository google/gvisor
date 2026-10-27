load("@rules_python//python:py_test.bzl", "py_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

py_test(
    name = "release_test",
    srcs = ["release_test.py"],
    args = ["$(rootpath //tools:make_kubernetes_release.py)"],
    data = ["//tools:make_kubernetes_release.py"],
)
