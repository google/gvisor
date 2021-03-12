load("//tools:defs.bzl", "go_binary")

licenses(["notice"])

go_binary(
    name = "measure_tool",
    srcs = [
        "measure_tool.go",
        "measure_tool_unsafe.go",
    ],
    pure = True,
    deps = [
        "//pkg/abi/linux",
    ],
)
