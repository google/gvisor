load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//visibility:public"],
    licenses = ["notice"],
)

go_template_instance(
    name = "control_fd_list",
    out = "control_fd_list.go",
    package = "lisafs",
    prefix = "controlFD",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*ControlFD",
        "Linker": "*ControlFD",
    },
)

go_template_instance(
    name = "open_fd_list",
    out = "open_fd_list.go",
    package = "lisafs",
    prefix = "openFD",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*OpenFD",
        "Linker": "*OpenFD",
    },
)

go_library(
    name = "lisafs",
    srcs = [
        "channel.go",
        "client.go",
        "client_file.go",
        "communicator.go",
        "connection.go",
        "control_fd_list.go",
        "fd.go",
        "handlers.go",
        "lisafs.go",
        "message.go",
        "node.go",
        "open_fd_list.go",
        "sample_message.go",
        "server.go",
        "sock.go",
    ],
    marshal = True,
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/cleanup",
        "//pkg/context",
        "//pkg/errors",
        "//pkg/errors/linuxerr",
        "//pkg/fdchannel",
        "//pkg/flipcall",
        "//pkg/fspath",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/marshal/primitive",
        "//pkg/p9",
        "//pkg/refs",
        "//pkg/sync",
        "//pkg/unet",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "sock_test",
    size = "small",
    srcs = ["sock_test.go"],
    library = ":lisafs",
    deps = [
        "//pkg/marshal",
        "//pkg/rand",
        "//pkg/sync",
        "//pkg/unet",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "connection_test",
    size = "small",
    srcs = ["connection_test.go"],
    deps = [
        ":lisafs",
        "//pkg/abi/linux",
        "//pkg/sync",
        "//pkg/unet",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "node_test",
    size = "small",
    srcs = ["node_test.go"],
    library = ":lisafs",
)
