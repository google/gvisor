load("@bazel_skylib//rules:run_binary.bzl", "run_binary")
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")

exports_files([
    "LICENSE",
    "NOTICE",
])

# Upstream compiles wrk.lua to an object and links it into the executable.
# https://github.com/giltene/wrk2/blob/44a94c17d/Makefile#L43-L54
# Emit C so the target compiler writes the object when cross-compiling. Both
# Linux targets use LuaJIT's GC64 bytecode format.
run_binary(
    name = "wrk_bytecode",
    srcs = [
        "src/wrk.lua",
        "@luajit//:src/jit/bcsave.lua",
    ],
    outs = ["wrk_bytecode.c"],
    args = [
        "-b",
        "-t",
        "c",
        "-n",
        "wrk",
        "$(execpath src/wrk.lua)",
        "$(execpath wrk_bytecode.c)",
    ],
    # -b loads jit.bcsave, the only external Lua module needed to emit C.
    env = {"LUA_PATH": "$(execpath @luajit//:src/jit/bcsave.lua)"},
    tool = "@luajit//:bin/luajit",
)

# The Linux compiler flags and source list follow wrk2's Makefile. glibc
# provides the BSD interfaces requested there under _DEFAULT_SOURCE.
# https://github.com/giltene/wrk2/blob/44a94c17d/Makefile#L1-L35
cc_library(
    name = "wrk",
    srcs = [
        "src/ae.c",
        "src/aprintf.c",
        "src/hdr_histogram.c",
        "src/http_parser.c",
        "src/net.c",
        "src/script.c",
        "src/ssl.c",
        "src/stats.c",
        "src/tinymt64.c",
        "src/units.c",
        "src/zmalloc.c",
    ],
    hdrs = glob(["src/*.h"]),
    copts = [
        "-std=c99",
        "-O2",
    ],
    includes = ["src"],
    linkopts = ["-pthread"],
    local_defines = [
        "_REENTRANT",
        "_POSIX_C_SOURCE=200809L",
        "_DEFAULT_SOURCE",
    ],
    target_compatible_with = ["@platforms//os:linux"],
    # ae.c includes the selected event backend into its own translation unit.
    # https://github.com/giltene/wrk2/blob/44a94c17d/src/ae.c#L47-L61
    textual_hdrs = glob(["src/ae_*.c"]),
    visibility = ["//visibility:public"],
    deps = [
        "@luajit",
        "@openssl//:ssl",
    ],
)

cc_binary(
    name = "wrk2",
    srcs = [
        "src/wrk.c",
        ":wrk_bytecode",
    ],
    copts = [
        "-std=c99",
        "-O2",
    ],
    # Export luaJIT_BC_wrk so LuaJIT can find the embedded module when
    # script_create calls require("wrk").
    # https://github.com/giltene/wrk2/blob/44a94c17d/Makefile#L16-L19
    # https://github.com/giltene/wrk2/blob/44a94c17d/src/script.c#L46-L51
    linkopts = [
        "-Wl,-E",
        "-Wl,--as-needed",
    ],
    linkstatic = True,
    local_defines = [
        "_REENTRANT",
        "_POSIX_C_SOURCE=200809L",
        "_DEFAULT_SOURCE",
    ],
    target_compatible_with = ["@platforms//os:linux"],
    visibility = ["//visibility:public"],
    deps = [":wrk"],
)
