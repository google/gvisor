load("//tools:defs.bzl", "go_binary")

licenses(["notice"])

go_binary(
    name = "go_marshal",
    srcs = ["main.go"],
    visibility = [
        "//:sandbox",
    ],
    deps = [
        "//tools/go_marshal/gomarshal",
    ],
)

config_setting(
    name = "marshal_config_verbose",
    values = {"define": "gomarshal=verbose"},
)
