package(licenses = ["notice"])

py_binary(
    name = "benchmarks",
    srcs = ["run.py"],
    data = [
        "//tools/images:ubuntu1604",
        "//tools/images:zone",
    ],
    main = "run.py",
    python_version = "PY3",
    srcs_version = "PY3",
    tags = [
        "local",
        "manual",
    ],
    deps = ["//benchmarks/runner"],
)
