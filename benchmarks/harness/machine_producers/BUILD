load("//benchmarks:defs.bzl", "py_library", "requirement")

package(
    default_visibility = ["//benchmarks:__subpackages__"],
    licenses = ["notice"],
)

py_library(
    name = "harness",
    srcs = ["__init__.py"],
)

py_library(
    name = "machine_producer",
    srcs = ["machine_producer.py"],
)

py_library(
    name = "mock_producer",
    srcs = ["mock_producer.py"],
    deps = [
        "//benchmarks/harness:machine",
        "//benchmarks/harness/machine_producers:machine_producer",
    ],
)

py_library(
    name = "yaml_producer",
    srcs = ["yaml_producer.py"],
    deps = [
        "//benchmarks/harness:machine",
        "//benchmarks/harness/machine_producers:machine_producer",
        requirement("PyYAML", False),
    ],
)
