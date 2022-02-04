load("//tools:defs.bzl", "bzl_library", "gotsan_flag_values", "gotsan_values")

package(licenses = ["notice"])

config_setting(
    name = "debug",
    values = {"compilation_mode": "dbg"},
    visibility = [
        "//:sandbox",
    ],
)

config_setting(
    name = "gotsan",
    flag_values = gotsan_flag_values,
    values = gotsan_values,
    visibility = [
        "//:sandbox",
    ],
)

bzl_library(
    name = "defs_bzl",
    srcs = ["defs.bzl"],
    visibility = [
        "//:sandbox",
    ],
)

bzl_library(
    name = "deps_bzl",
    srcs = ["deps.bzl"],
    visibility = [
        "//:sandbox",
    ],
)
