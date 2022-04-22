load("//tools:defs.bzl", "go_library", "go_test")

licenses(["notice"])

go_library(
    name = "syncevent",
    srcs = [
        "broadcaster.go",
        "receiver.go",
        "source.go",
        "syncevent.go",
        "waiter_unsafe.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/sync",
    ],
)

go_test(
    name = "syncevent_test",
    size = "small",
    srcs = [
        "broadcaster_test.go",
        "syncevent_example_test.go",
        "waiter_test.go",
    ],
    library = ":syncevent",
    deps = [
        "//pkg/atomicbitops",
        "//pkg/sleep",
        "//pkg/sync",
        "//pkg/waiter",
    ],
)
