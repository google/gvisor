load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(
    default_visibility = ["//visibility:public"],
    licenses = ["notice"],
)

go_template_instance(
    name = "control_fd_refs",
    out = "control_fd_refs.go",
    package = "lisafs",
    prefix = "controlFD",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "ControlFD",
    },
)

go_template_instance(
    name = "open_fd_refs",
    out = "open_fd_refs.go",
    package = "lisafs",
    prefix = "openFD",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "OpenFD",
    },
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
        "control_fd_refs.go",
        "fd.go",
        "handlers.go",
        "lisafs.go",
        "message.go",
        "open_fd_list.go",
        "open_fd_refs.go",
        "sample_message.go",
        "server.go",
        "sock.go",
    ],
    marshal = True,
    deps = [
        "//pkg/abi/linux",
        "//pkg/cleanup",
        "//pkg/context",
        "//pkg/fdchannel",
        "//pkg/flipcall",
        "//pkg/fspath",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/marshal/primitive",
        "//pkg/p9",
        "//pkg/refsvfs2",
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
        "//pkg/sync",
        "//pkg/unet",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
