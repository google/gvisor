load("//tools:defs.bzl", "bzl_library")

package(licenses = ["notice"])

config_setting(
    name = "gcloud_rule",
    values = {
        "define": "gcloud=off",
    },
)

py_binary(
    name = "benchmarks",
    testonly = 1,
    srcs = ["run.py"],
    data = select({
        ":gcloud_rule": [],
        "//conditions:default": [
            "//tools/vm:ubuntu1604",
            "//tools/vm:zone",
        ],
    }),
    main = "run.py",
    python_version = "PY3",
    srcs_version = "PY3",
    tags = [
        "local",
        "manual",
    ],
    deps = ["//benchmarks/runner"],
)

bzl_library(
    name = "defs_bzl",
    srcs = ["defs.bzl"],
    visibility = ["//visibility:private"],
)
