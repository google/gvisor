load("//tools:defs.bzl", "py_library", "py_requirement", "py_test")

package(licenses = ["notice"])

py_library(
    name = "runner",
    srcs = ["__init__.py"],
    data = [
        "//benchmarks/workloads:files",
    ],
    visibility = ["//benchmarks:__pkg__"],
    deps = [
        ":commands",
        "//benchmarks/harness:benchmark_driver",
        "//benchmarks/harness/machine_producers:machine_producer",
        "//benchmarks/harness/machine_producers:mock_producer",
        "//benchmarks/harness/machine_producers:yaml_producer",
        "//benchmarks/suites",
        "//benchmarks/suites:absl",
        "//benchmarks/suites:density",
        "//benchmarks/suites:fio",
        "//benchmarks/suites:helpers",
        "//benchmarks/suites:http",
        "//benchmarks/suites:media",
        "//benchmarks/suites:ml",
        "//benchmarks/suites:network",
        "//benchmarks/suites:redis",
        "//benchmarks/suites:startup",
        "//benchmarks/suites:sysbench",
        "//benchmarks/suites:syscall",
        py_requirement("click", True),
    ],
)

py_library(
    name = "commands",
    srcs = ["commands.py"],
    deps = [
        py_requirement("click", True),
    ],
)

py_test(
    name = "runner_test",
    srcs = ["runner_test.py"],
    python_version = "PY3",
    tags = [
        "local",
        "manual",
    ],
    deps = [
        ":runner",
        py_requirement("click", True),
        py_requirement("attrs", False),
        py_requirement("atomicwrites", False),
        py_requirement("more-itertools", False),
        py_requirement("pathlib2", False),
        py_requirement("pluggy", False),
        py_requirement("py", False),
        py_requirement("pytest", True),
        py_requirement("six", False),
    ],
)
