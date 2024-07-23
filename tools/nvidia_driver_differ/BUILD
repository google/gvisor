load("//tools:defs.bzl", "cc_binary", "go_test")

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
    deps = [
        "@llvm-project//clang:ast",
        "@llvm-project//clang:ast_matchers",
        "@llvm-project//clang:tooling",
        "@llvm-project//llvm:Support",
        "@nlohmann_json//:json",
    ],
)

go_test(
    name = "driver_ast_parser_test",
    srcs = ["driver_ast_parser_test.go"],
    data = [
        "test_struct.cc",
        ":driver_ast_parser",
    ],
    deps = [
        "//pkg/test/testutil",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@com_github_google_go_cmp//cmp/cmpopts:go_default_library",
    ],
)
