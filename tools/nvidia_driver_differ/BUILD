load("//tools:defs.bzl", "build_test", "cc_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

cc_binary(
    name = "driver_ast_parser",
    srcs = [
        "driver_ast_parser.cc",
        "driver_ast_parser.h",
    ],
)

build_test(
    name = "driver_ast_parser_test",
    targets = [":driver_ast_parser"],
)
