load("@rules_python//python:defs.bzl", "py_test")
load("//website:defs.bzl", "doc")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//website:__pkg__"],
    licenses = ["notice"],
)

doc(
    name = "go",
    src = "go.md",
    category = "SDK/API Reference",
    permalink = "/docs/sdk/go/",
    subcategory = "Go",
    weight = "10",
)

doc(
    name = "quickstart",
    src = "quickstart.md",
    category = "SDK/API Reference",
    permalink = "/docs/sdk/go/quickstart/",
    subcategory = "Go",
    weight = "20",
)

doc(
    name = "python",
    src = "python.md",
    category = "SDK/API Reference",
    permalink = "/docs/sdk/python/",
    subcategory = "Python",
    weight = "10",
)

doc(
    name = "python_quickstart",
    src = "python_quickstart.md",
    category = "SDK/API Reference",
    permalink = "/docs/sdk/python/quickstart/",
    subcategory = "Python",
    weight = "20",
)

py_test(
    name = "python_docs_api_test",
    srcs = ["python_docs_api_test.py"],
    data = [
        "python.md",
        "//sandboxexec/sandbox/python:gvisor/sandbox.py",
    ],
)
