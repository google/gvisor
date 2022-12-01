load("//tools:defs.bzl", "go_library", "go_test", "more_shards")

package(licenses = ["notice"])

go_test(
    name = "tcp_test",
    size = "large",
    srcs = ["tcp_test.go"],
    shard_count = more_shards,
    deps = [
        ":e2e",
        "//pkg/bufferv2",
        "//pkg/rand",
        "//pkg/refs",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/checker",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/loopback",
        "//pkg/tcpip/link/sniffer",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/network/ipv6",
        "//pkg/tcpip/seqnum",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/testutil",
        "//pkg/tcpip/transport/tcp",
        "//pkg/tcpip/transport/tcp/testing/context",
        "//pkg/test/testutil",
        "//pkg/waiter",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)

go_test(
    name = "dual_stack_test",
    size = "small",
    srcs = ["dual_stack_test.go"],
    deps = [
        ":e2e",
        "//pkg/refs",
        "//pkg/tcpip",
        "//pkg/tcpip/checker",
        "//pkg/tcpip/header",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/seqnum",
        "//pkg/tcpip/transport/tcp",
        "//pkg/tcpip/transport/tcp/testing/context",
        "//pkg/waiter",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)

go_library(
    name = "e2e",
    testonly = 1,
    srcs = ["e2e.go"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/checker",
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "//pkg/tcpip/transport/tcp",
        "//pkg/tcpip/transport/tcp/testing/context",
        "//pkg/waiter",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)

go_test(
    name = "forwarder_test",
    size = "small",
    srcs = ["forwarder_test.go"],
    deps = [
        ":e2e",
        "//pkg/refs",
        "//pkg/tcpip",
        "//pkg/tcpip/checker",
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "//pkg/tcpip/transport/tcp",
        "//pkg/tcpip/transport/tcp/testing/context",
    ],
)

go_test(
    name = "rcv_test",
    size = "small",
    srcs = ["rcv_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
    ],
)

go_test(
    name = "sack_scoreboard_test",
    size = "small",
    srcs = ["sack_scoreboard_test.go"],
    deps = [
        "//pkg/refs",
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "//pkg/tcpip/transport/tcp",
    ],
)

go_test(
    name = "tcp_timestamp_test",
    size = "small",
    srcs = ["tcp_timestamp_test.go"],
    deps = [
        ":e2e",
        "//pkg/refs",
        "//pkg/tcpip",
        "//pkg/tcpip/checker",
        "//pkg/tcpip/header",
        "//pkg/tcpip/transport/tcp",
        "//pkg/tcpip/transport/tcp/testing/context",
        "//pkg/waiter",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)

go_test(
    name = "tcp_rack_test",
    size = "small",
    srcs = ["tcp_rack_test.go"],
    deps = [
        ":e2e",
        "//pkg/bufferv2",
        "//pkg/refs",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/tcp/testing/context",
        "//pkg/test/testutil",
    ],
)

go_test(
    name = "tcp_sack_test",
    size = "small",
    srcs = ["tcp_sack_test.go"],
    deps = [
        ":e2e",
        "//pkg/bufferv2",
        "//pkg/refs",
        "//pkg/tcpip",
        "//pkg/tcpip/checker",
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/tcp",
        "//pkg/tcpip/transport/tcp/testing/context",
        "//pkg/test/testutil",
    ],
)

go_test(
    name = "tcp_noracedetector_test",
    size = "small",
    srcs = ["tcp_noracedetector_test.go"],
    # These tests can be extremely slow/flaky when run under gotsan,
    # so exclude them from gotsan runs.
    tags = ["nogotsan"],
    deps = [
        ":e2e",
        "//pkg/refs",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/transport/tcp",
        "//pkg/tcpip/transport/tcp/testing/context",
        "//pkg/test/testutil",
    ],
)
