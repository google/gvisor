load("//tools:defs.bzl", "py_library", "py_requirement")

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
        "//benchmarks/harness/machine_producers:gcloud_producer",
        "//benchmarks/harness/machine_producers:machine_producer",
    ],
)

py_library(
    name = "yaml_producer",
    srcs = ["yaml_producer.py"],
    deps = [
        "//benchmarks/harness:machine",
        "//benchmarks/harness/machine_producers:machine_producer",
        py_requirement(
            "PyYAML",
            direct = False,
        ),
    ],
)

py_library(
    name = "gcloud_mock_recorder",
    srcs = ["gcloud_mock_recorder.py"],
)

py_library(
    name = "gcloud_producer",
    srcs = ["gcloud_producer.py"],
    deps = [
        "//benchmarks/harness:machine",
        "//benchmarks/harness/machine_producers:gcloud_mock_recorder",
        "//benchmarks/harness/machine_producers:machine_producer",
    ],
)

filegroup(
    name = "test_data",
    srcs = [
        "testdata/get_five.json",
        "testdata/get_one.json",
    ],
)

py_library(
    name = "gcloud_producer_test_lib",
    srcs = ["gcloud_producer_test.py"],
    deps = [
        "//benchmarks/harness/machine_producers:machine_producer",
        "//benchmarks/harness/machine_producers:mock_producer",
    ],
)

py_test(
    name = "gcloud_producer_test",
    srcs = [":gcloud_producer_test_lib"],
    data = [
        ":test_data",
    ],
    python_version = "PY3",
    tags = [
        "local",
        "manual",
    ],
)
