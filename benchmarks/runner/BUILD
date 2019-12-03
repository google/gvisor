load("//benchmarks:defs.bzl", "py_library", "py_test", "requirement")

package(licenses = ["notice"])

py_library(
    name = "runner",
    srcs = ["__init__.py"],
    data = [
        "//benchmarks/workloads:files",
    ],
    visibility = ["//benchmarks:__pkg__"],
    deps = [
        "//benchmarks/harness:benchmark_driver",
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
        requirement("click", True),
    ],
)

py_test(
    name = "runner_test",
    srcs = ["runner_test.py"],
    python_version = "PY3",
    tags = ["local"],
    deps = [
        ":runner",
        requirement("click", True),
        requirement("attrs", False),
        requirement("atomicwrites", False),
        requirement("more-itertools", False),
        requirement("pathlib2", False),
        requirement("pluggy", False),
        requirement("py", False),
        requirement("pytest", True),
        requirement("six", False),
    ],
)
