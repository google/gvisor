package(
    default_visibility = ["//benchmarks:__subpackages__"],
    licenses = ["notice"],
)

py_library(
    name = "suites",
    srcs = ["__init__.py"],
)

py_library(
    name = "absl",
    srcs = ["absl.py"],
    deps = [
        "//benchmarks/harness:machine",
        "//benchmarks/suites",
        "//benchmarks/workloads/absl",
    ],
)

py_library(
    name = "density",
    srcs = ["density.py"],
    deps = [
        "//benchmarks/harness:container",
        "//benchmarks/harness:machine",
        "//benchmarks/suites",
        "//benchmarks/suites:helpers",
    ],
)

py_library(
    name = "fio",
    srcs = ["fio.py"],
    deps = [
        "//benchmarks/harness:machine",
        "//benchmarks/suites",
        "//benchmarks/suites:helpers",
        "//benchmarks/workloads/fio",
    ],
)

py_library(
    name = "helpers",
    srcs = ["helpers.py"],
    deps = ["//benchmarks/harness:machine"],
)

py_library(
    name = "http",
    srcs = ["http.py"],
    deps = [
        "//benchmarks/harness:machine",
        "//benchmarks/suites",
        "//benchmarks/workloads/ab",
    ],
)

py_library(
    name = "media",
    srcs = ["media.py"],
    deps = [
        "//benchmarks/harness:machine",
        "//benchmarks/suites",
        "//benchmarks/suites:helpers",
        "//benchmarks/workloads/ffmpeg",
    ],
)

py_library(
    name = "ml",
    srcs = ["ml.py"],
    deps = [
        "//benchmarks/harness:machine",
        "//benchmarks/suites",
        "//benchmarks/suites:startup",
        "//benchmarks/workloads/tensorflow",
    ],
)

py_library(
    name = "network",
    srcs = ["network.py"],
    deps = [
        "//benchmarks/harness:machine",
        "//benchmarks/suites",
        "//benchmarks/suites:helpers",
        "//benchmarks/workloads/iperf",
    ],
)

py_library(
    name = "redis",
    srcs = ["redis.py"],
    deps = [
        "//benchmarks/harness:machine",
        "//benchmarks/suites",
        "//benchmarks/workloads/redisbenchmark",
    ],
)

py_library(
    name = "startup",
    srcs = ["startup.py"],
    deps = [
        "//benchmarks/harness:machine",
        "//benchmarks/suites",
        "//benchmarks/suites:helpers",
    ],
)

py_library(
    name = "sysbench",
    srcs = ["sysbench.py"],
    deps = [
        "//benchmarks/harness:machine",
        "//benchmarks/suites",
        "//benchmarks/workloads/sysbench",
    ],
)

py_library(
    name = "syscall",
    srcs = ["syscall.py"],
    deps = [
        "//benchmarks/harness:machine",
        "//benchmarks/suites",
        "//benchmarks/workloads/syscall",
    ],
)
