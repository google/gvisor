load("//tools:defs.bzl", "cc_binary", "cc_library", "gbenchmark", "gtest", "select_arch", "select_system")

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

exports_files(
    [
        "packet_socket.cc",
        "packet_socket_dgram.cc",
        "packet_socket_raw.cc",
        "raw_socket.cc",
        "raw_socket_hdrincl.cc",
        "raw_socket_icmp.cc",
        "socket.cc",
        "socket_inet_loopback.cc",
        "socket_inet_loopback_isolated.cc",
        "socket_inet_loopback_test_params.h",
        "socket_ip_loopback_blocking.cc",
        "socket_ip_tcp_generic_loopback.cc",
        "socket_ip_tcp_loopback.cc",
        "socket_ip_tcp_loopback_blocking.cc",
        "socket_ip_tcp_loopback_nonblock.cc",
        "socket_ip_tcp_udp_generic.cc",
        "socket_ip_udp_loopback.cc",
        "socket_ip_udp_loopback_blocking.cc",
        "socket_ip_udp_loopback_nonblock.cc",
        "socket_ip_unbound.cc",
        "socket_ipv4_datagram_based_socket_unbound_loopback.cc",
        "socket_ipv4_udp_unbound_external_networking_test.cc",
        "socket_ipv6_udp_unbound_external_networking_test.cc",
        "socket_ipv4_udp_unbound_loopback.cc",
        "socket_ipv6_udp_unbound_loopback.cc",
        "socket_ipv4_udp_unbound_loopback_nogotsan.cc",
        "tcp_socket.cc",
        "udp_bind.cc",
        "udp_socket.cc",
    ],
    visibility = ["//:sandbox"],
)

cc_binary(
    name = "sigaltstack_check",
    testonly = 1,
    srcs = ["sigaltstack_check.cc"],
    deps = ["//test/util:logging"],
)

cc_binary(
    name = "exec_assert_closed_workload",
    testonly = 1,
    srcs = ["exec_assert_closed_workload.cc"],
    deps = [
        "@com_google_absl//absl/strings",
    ],
)

cc_binary(
    name = "exec_basic_workload",
    testonly = 1,
    srcs = [
        "exec.h",
        "exec_basic_workload.cc",
    ],
)

cc_binary(
    name = "exec_proc_exe_workload",
    testonly = 1,
    srcs = ["exec_proc_exe_workload.cc"],
    deps = [
        "//test/util:fs_util",
        "//test/util:posix_error",
    ],
)

cc_binary(
    name = "exec_state_workload",
    testonly = 1,
    srcs = ["exec_state_workload.cc"],
    deps = ["@com_google_absl//absl/strings"],
)

sh_binary(
    name = "exit_script",
    testonly = 1,
    srcs = [
        "exit_script.sh",
    ],
)

cc_binary(
    name = "priority_execve",
    testonly = 1,
    srcs = [
        "priority_execve.cc",
    ],
)

cc_library(
    name = "base_poll_test",
    testonly = 1,
    srcs = ["base_poll_test.cc"],
    hdrs = ["base_poll_test.h"],
    deps = [
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:logging",
        "//test/util:signal_util",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_library(
    name = "file_base",
    testonly = 1,
    hdrs = ["file_base.h"],
    deps = [
        "//test/util:file_descriptor",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:test_util",
    ],
)

cc_library(
    name = "socket_netlink_util",
    testonly = 1,
    srcs = ["socket_netlink_util.cc"],
    hdrs = ["socket_netlink_util.h"],
    deps = [
        "//test/util:file_descriptor",
        "//test/util:posix_error",
        "//test/util:socket_util",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "socket_netlink_route_util",
    testonly = 1,
    srcs = ["socket_netlink_route_util.cc"],
    hdrs = ["socket_netlink_route_util.h"],
    deps = [
        ":socket_netlink_util",
    ],
)

cc_library(
    name = "unix_domain_socket_test_util",
    testonly = 1,
    srcs = ["unix_domain_socket_test_util.cc"],
    hdrs = ["unix_domain_socket_test_util.h"],
    deps = [
        "//test/util:socket_util",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:test_util",
    ],
)

cc_library(
    name = "ip_socket_test_util",
    testonly = 1,
    srcs = ["ip_socket_test_util.cc"],
    hdrs = ["ip_socket_test_util.h"],
    deps = [
        "//test/util:socket_util",
        "@com_google_absl//absl/strings",
    ],
)

cc_binary(
    name = "clock_nanosleep_test",
    testonly = 1,
    srcs = ["clock_nanosleep.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:cleanup",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:posix_error",
        "//test/util:signal_util",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
        "//test/util:timer_util",
    ],
)

cc_binary(
    name = "32bit_test",
    testonly = 1,
    srcs = ["32bit.cc"],
    linkstatic = 1,
    deps = [
        "@com_google_absl//absl/base:core_headers",
        gtest,
        "//test/util:memory_util",
        "//test/util:platform_util",
        "//test/util:posix_error",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "accept_bind_test",
    testonly = 1,
    srcs = ["accept_bind.cc"],
    linkstatic = 1,
    deps = [
        ":unix_domain_socket_test_util",
        "//test/util:file_descriptor",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "accept_bind_stream_test",
    testonly = 1,
    srcs = ["accept_bind_stream.cc"],
    linkstatic = 1,
    deps = [
        ":unix_domain_socket_test_util",
        "//test/util:file_descriptor",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "access_test",
    testonly = 1,
    srcs = ["access.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:fs_util",
        gtest,
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "affinity_test",
    testonly = 1,
    srcs = ["affinity.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:cleanup",
        "//test/util:fs_util",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:posix_error",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "aio_test",
    testonly = 1,
    srcs = [
        "aio.cc",
        "file_base.h",
    ],
    linkstatic = 1,
    deps = [
        "//test/util:cleanup",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:memory_util",
        "//test/util:posix_error",
        "//test/util:proc_util",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "alarm_test",
    testonly = 1,
    srcs = ["alarm.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:logging",
        "//test/util:signal_util",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "bad_test",
    testonly = 1,
    srcs = ["bad.cc"],
    linkstatic = 1,
    visibility = [
        "//:sandbox",
    ],
    deps = [
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "bind_test",
    testonly = 1,
    srcs = ["bind.cc"],
    linkstatic = 1,
    deps = [
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_test",
    testonly = 1,
    srcs = ["socket.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:socket_util",
        gtest,
        "//test/util:file_descriptor",
        "//test/util:temp_umask",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_capability_test",
    testonly = 1,
    srcs = ["socket_capability.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:file_descriptor",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "brk_test",
    testonly = 1,
    srcs = ["brk.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "chdir_test",
    testonly = 1,
    srcs = ["chdir.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        gtest,
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "chmod_test",
    testonly = 1,
    srcs = ["chmod.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        gtest,
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "chown_test",
    testonly = 1,
    srcs = ["chown.cc"],
    linkstatic = 1,
    # We require additional UIDs for this test, so don't include the bazel
    # sandbox as standard.
    tags = ["no-sandbox"],
    deps = [
        "//test/util:capability_util",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/synchronization",
        gtest,
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "sticky_test",
    testonly = 1,
    srcs = ["sticky.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "@com_google_absl//absl/flags:flag",
        gtest,
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "chroot_test",
    testonly = 1,
    srcs = ["chroot.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:cleanup",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "@com_google_absl//absl/cleanup",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:logging",
        "//test/util:mount_util",
        "//test/util:multiprocess_util",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "clock_getres_test",
    testonly = 1,
    srcs = ["clock_getres.cc"],
    linkstatic = 1,
    deps = [
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "clock_gettime_test",
    testonly = 1,
    srcs = ["clock_gettime.cc"],
    linkstatic = 1,
    deps = [
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "concurrency_test",
    testonly = 1,
    srcs = ["concurrency.cc"],
    linkstatic = 1,
    deps = [
        gbenchmark,
        gtest,
        "//test/util:platform_util",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
    ],
)

cc_binary(
    name = "connect_external_test",
    testonly = 1,
    srcs = ["connect_external.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "creat_test",
    testonly = 1,
    srcs = ["creat.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:fs_util",
        gtest,
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "dev_test",
    testonly = 1,
    srcs = ["dev.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "dup_test",
    testonly = 1,
    srcs = ["dup.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:eventfd_util",
        "//test/util:file_descriptor",
        "@com_google_absl//absl/memory",
        gtest,
        "//test/util:fs_util",
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "epoll_test",
    testonly = 1,
    srcs = ["epoll.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:epoll_util",
        "//test/util:eventfd_util",
        "//test/util:file_descriptor",
        gtest,
        "//test/util:posix_error",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "eventfd_test",
    testonly = 1,
    srcs = ["eventfd.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:epoll_util",
        "//test/util:eventfd_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "exceptions_test",
    testonly = 1,
    srcs = ["exceptions.cc"],
    linkstatic = 1,
    deps = [
        gtest,
        "//test/util:logging",
        "//test/util:platform_util",
        "//test/util:signal_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "getcpu_test",
    testonly = 1,
    srcs = ["getcpu.cc"],
    linkstatic = 1,
    deps = [
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "getcpu_host_test",
    testonly = 1,
    srcs = ["getcpu.cc"],
    linkstatic = 1,
    deps = [
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "getrusage_test",
    testonly = 1,
    srcs = ["getrusage.cc"],
    linkstatic = 1,
    deps = [
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:logging",
        "//test/util:memory_util",
        "//test/util:multiprocess_util",
        "//test/util:signal_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "exec_binary_test",
    testonly = 1,
    srcs = ["exec_binary.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:cleanup",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:multiprocess_util",
        "//test/util:posix_error",
        "//test/util:proc_util",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "exec_test",
    testonly = 1,
    srcs = [
        "exec.cc",
        "exec.h",
    ],
    data = [
        ":exec_assert_closed_workload",
        ":exec_basic_workload",
        ":exec_proc_exe_workload",
        ":exec_state_workload",
        ":exit_script",
        ":priority_execve",
    ],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/types:optional",
        gtest,
        "//test/util:multiprocess_util",
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "exit_test",
    testonly = 1,
    srcs = ["exit.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:time_util",
    ],
)

cc_binary(
    name = "fallocate_test",
    testonly = 1,
    srcs = ["fallocate.cc"],
    linkstatic = 1,
    deps = [
        ":file_base",
        "//test/util:cleanup",
        "//test/util:eventfd_util",
        "//test/util:file_descriptor",
        "//test/util:socket_util",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "fault_test",
    testonly = 1,
    srcs = ["fault.cc"],
    linkstatic = 1,
    deps = [
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "fchdir_test",
    testonly = 1,
    srcs = ["fchdir.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        gtest,
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "fcntl_test",
    testonly = 1,
    srcs = ["fcntl.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:cleanup",
        "//test/util:eventfd_util",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "//test/util:socket_util",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:memory_util",
        "//test/util:multiprocess_util",
        "//test/util:posix_error",
        "//test/util:save_util",
        "//test/util:signal_util",
        "//test/util:temp_path",
        "//test/util:test_util",
        "//test/util:thread_util",
        "//test/util:timer_util",
    ],
)

cc_binary(
    name = "flock_test",
    testonly = 1,
    srcs = [
        "file_base.h",
        "flock.cc",
    ],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "//test/util:socket_util",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:epoll_util",
        "//test/util:eventfd_util",
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
        "//test/util:timer_util",
    ],
)

cc_binary(
    name = "fork_test",
    testonly = 1,
    srcs = ["fork.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:logging",
        "//test/util:memory_util",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "fpsig_fork_test",
    testonly = 1,
    srcs = ["fpsig_fork.cc"],
    linkstatic = 1,
    deps = [
        gtest,
        "//test/util:logging",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "fpsig_nested_test",
    testonly = 1,
    srcs = ["fpsig_nested.cc"],
    linkstatic = 1,
    deps = [
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "sync_file_range_test",
    testonly = 1,
    srcs = ["sync_file_range.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        gtest,
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "fsync_test",
    testonly = 1,
    srcs = ["fsync.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        gtest,
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "futex_test",
    testonly = 1,
    srcs = ["futex.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:cleanup",
        "//test/util:file_descriptor",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:memory_util",
        "//test/util:save_util",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
        "//test/util:time_util",
        "//test/util:timer_util",
    ],
)

cc_binary(
    name = "getdents_test",
    testonly = 1,
    srcs = ["getdents.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:eventfd_util",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "@com_google_absl//absl/container:node_hash_map",
        "@com_google_absl//absl/container:node_hash_set",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "verity_getdents_test",
    testonly = 1,
    srcs = ["verity_getdents.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        gtest,
        "//test/util:fs_util",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:verity_util",
    ],
)

cc_binary(
    name = "getrandom_test",
    testonly = 1,
    srcs = ["getrandom.cc"],
    linkstatic = 1,
    deps = [
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "inotify_test",
    testonly = 1,
    srcs = ["inotify.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:epoll_util",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "//test/util:multiprocess_util",
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
    ],
)

cc_binary(
    name = "ioctl_test",
    testonly = 1,
    srcs = ["ioctl.cc"],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        ":unix_domain_socket_test_util",
        "//test/util:file_descriptor",
        "//test/util:socket_util",
        gtest,
        "//test/util:signal_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "verity_ioctl_test",
    testonly = 1,
    srcs = ["verity_ioctl.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        gtest,
        "//test/util:fs_util",
        "//test/util:mount_util",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:verity_util",
    ],
)

cc_library(
    name = "iptables_types",
    testonly = 1,
    hdrs = [
        "iptables.h",
    ],
)

cc_binary(
    name = "iptables_test",
    testonly = 1,
    srcs = [
        "iptables.cc",
    ],
    linkstatic = 1,
    deps = [
        ":iptables_types",
        "//test/util:capability_util",
        "//test/util:file_descriptor",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "ip6tables_test",
    testonly = 1,
    srcs = [
        "ip6tables.cc",
    ],
    linkstatic = 1,
    deps = [
        ":iptables_types",
        "//test/util:capability_util",
        "//test/util:file_descriptor",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "itimer_test",
    testonly = 1,
    srcs = ["itimer.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:logging",
        "//test/util:multiprocess_util",
        "//test/util:posix_error",
        "//test/util:signal_util",
        "//test/util:test_util",
        "//test/util:thread_util",
        "//test/util:timer_util",
    ],
)

cc_binary(
    name = "kcov_test",
    testonly = 1,
    srcs = ["kcov.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:file_descriptor",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "kill_test",
    testonly = 1,
    srcs = ["kill.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:file_descriptor",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:logging",
        "//test/util:signal_util",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "link_test",
    testonly = 1,
    srcs = ["link.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "lseek_test",
    testonly = 1,
    srcs = ["lseek.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        gtest,
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "madvise_test",
    testonly = 1,
    srcs = ["madvise.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        gtest,
        "//test/util:logging",
        "//test/util:memory_util",
        "//test/util:multiprocess_util",
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "membarrier_test",
    testonly = 1,
    srcs = ["membarrier.cc"],
    linkstatic = 1,
    deps = [
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:cleanup",
        "//test/util:logging",
        "//test/util:memory_util",
        "//test/util:posix_error",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "mempolicy_test",
    testonly = 1,
    srcs = ["mempolicy.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:cleanup",
        "@com_google_absl//absl/memory",
        gtest,
        "//test/util:memory_util",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "mincore_test",
    testonly = 1,
    srcs = ["mincore.cc"],
    linkstatic = 1,
    deps = [
        gtest,
        "//test/util:memory_util",
        "//test/util:posix_error",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "mkdir_test",
    testonly = 1,
    srcs = ["mkdir.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:fs_util",
        gtest,
        "//test/util:temp_path",
        "//test/util:temp_umask",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "mknod_test",
    testonly = 1,
    srcs = ["mknod.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        gtest,
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "fifo_test",
    testonly = 1,
    srcs = ["fifo.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        gtest,
        "//test/util:signal_util",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
        "//test/util:timer_util",
    ],
)

cc_binary(
    name = "mlock_test",
    testonly = 1,
    srcs = ["mlock.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:cleanup",
        gtest,
        "//test/util:memory_util",
        "//test/util:multiprocess_util",
        "//test/util:rlimit_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "mmap_test",
    testonly = 1,
    srcs = ["mmap.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:cleanup",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:memory_util",
        "//test/util:multiprocess_util",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "verity_mmap_test",
    testonly = 1,
    srcs = ["verity_mmap.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        gtest,
        "//test/util:fs_util",
        "//test/util:memory_util",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:verity_util",
    ],
)

cc_binary(
    name = "mount_test",
    testonly = 1,
    srcs = ["mount.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:mount_util",
        "//test/util:multiprocess_util",
        "//test/util:posix_error",
        "//test/util:save_util",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "verity_mount_test",
    testonly = 1,
    srcs = ["verity_mount.cc"],
    linkstatic = 1,
    deps = [
        gtest,
        "//test/util:capability_util",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:verity_util",
    ],
)

cc_binary(
    name = "mremap_test",
    testonly = 1,
    srcs = ["mremap.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:logging",
        "//test/util:memory_util",
        "//test/util:multiprocess_util",
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "msync_test",
    testonly = 1,
    srcs = ["msync.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "//test/util:memory_util",
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "munmap_test",
    testonly = 1,
    srcs = ["munmap.cc"],
    linkstatic = 1,
    deps = [
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "open_test",
    testonly = 1,
    srcs = [
        "file_base.h",
        "open.cc",
    ],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:cleanup",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "open_create_test",
    testonly = 1,
    srcs = ["open_create.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        gtest,
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:temp_umask",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "packet_socket_dgram_test",
    testonly = 1,
    srcs = ["packet_socket_dgram.cc"],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        ":unix_domain_socket_test_util",
        "//test/util:capability_util",
        "//test/util:cleanup",
        "//test/util:file_descriptor",
        "//test/util:socket_util",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/base:endian",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "packet_socket_raw_test",
    testonly = 1,
    srcs = ["packet_socket_raw.cc"],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        ":unix_domain_socket_test_util",
        "//test/util:capability_util",
        "//test/util:cleanup",
        "//test/util:file_descriptor",
        "//test/util:socket_util",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/base:endian",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "packet_socket_test",
    testonly = 1,
    srcs = ["packet_socket.cc"],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        "//test/util:capability_util",
        "//test/util:file_descriptor",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
    ],
)

cc_binary(
    name = "pty_test",
    testonly = 1,
    srcs = ["pty.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:file_descriptor",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:cleanup",
        "//test/util:posix_error",
        "//test/util:pty_util",
        "//test/util:signal_util",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "pty_root_test",
    testonly = 1,
    srcs = ["pty_root.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:file_descriptor",
        "@com_google_absl//absl/base:core_headers",
        gtest,
        "//test/util:posix_error",
        "//test/util:pty_util",
        "//test/util:test_main",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "partial_bad_buffer_test",
    testonly = 1,
    # Android does not support preadv or pwritev in r22.
    srcs = select_system(linux = ["partial_bad_buffer.cc"]),
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "//test/util:socket_util",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "pause_test",
    testonly = 1,
    srcs = ["pause.cc"],
    linkstatic = 1,
    deps = [
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:signal_util",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "ping_socket_test",
    testonly = 1,
    srcs = ["ping_socket.cc"],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        "//test/util:file_descriptor",
        "//test/util:socket_util",
        "@com_google_absl//absl/algorithm:container",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:optional",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "pipe_test",
    testonly = 1,
    srcs = ["pipe.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:posix_error",
        "//test/util:signal_util",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "poll_test",
    testonly = 1,
    srcs = ["poll.cc"],
    linkstatic = 1,
    deps = [
        ":base_poll_test",
        "//test/util:eventfd_util",
        "//test/util:file_descriptor",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:logging",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "ppoll_test",
    testonly = 1,
    srcs = ["ppoll.cc"],
    linkstatic = 1,
    deps = [
        ":base_poll_test",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:signal_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "arch_prctl_test",
    testonly = 1,
    srcs = select_arch(
        amd64 = ["arch_prctl.cc"],
        arm64 = [],
    ),
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "prctl_test",
    testonly = 1,
    srcs = ["prctl.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:cleanup",
        "@com_google_absl//absl/flags:flag",
        gtest,
        "//test/util:multiprocess_util",
        "//test/util:posix_error",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "prctl_setuid_test",
    testonly = 1,
    srcs = ["prctl_setuid.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "@com_google_absl//absl/flags:flag",
        gtest,
        "//test/util:logging",
        "//test/util:multiprocess_util",
        "//test/util:posix_error",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "pread64_test",
    testonly = 1,
    srcs = ["pread64.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        gtest,
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "preadv_test",
    testonly = 1,
    srcs = ["preadv.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:logging",
        "//test/util:memory_util",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
        "//test/util:timer_util",
    ],
)

cc_binary(
    name = "preadv2_test",
    testonly = 1,
    srcs = [
        "file_base.h",
        "preadv2.cc",
    ],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "priority_test",
    testonly = 1,
    srcs = ["priority.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:fs_util",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "proc_test",
    testonly = 1,
    srcs = ["proc.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:cleanup",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "//test/util:mount_util",
        "@com_google_absl//absl/container:node_hash_set",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:memory_util",
        "//test/util:multiprocess_util",
        "//test/util:posix_error",
        "//test/util:proc_util",
        "//test/util:temp_path",
        "//test/util:test_util",
        "//test/util:thread_util",
        "//test/util:time_util",
        "//test/util:timer_util",
    ],
)

cc_binary(
    name = "proc_isolated_test",
    testonly = 1,
    srcs = ["proc_isolated.cc"],
    linkstatic = 1,
    deps = [
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:fs_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "proc_net_test",
    testonly = 1,
    srcs = ["proc_net.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "//test/util:socket_util",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "proc_pid_oomscore_test",
    testonly = 1,
    srcs = ["proc_pid_oomscore.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:fs_util",
        "//test/util:test_main",
        "//test/util:test_util",
        "@com_google_absl//absl/strings",
    ],
)

cc_binary(
    name = "proc_pid_smaps_test",
    testonly = 1,
    srcs = ["proc_pid_smaps.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/types:optional",
        gtest,
        "//test/util:memory_util",
        "//test/util:posix_error",
        "//test/util:proc_util",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "proc_pid_uid_gid_map_test",
    testonly = 1,
    srcs = ["proc_pid_uid_gid_map.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:cleanup",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:logging",
        "//test/util:multiprocess_util",
        "//test/util:posix_error",
        "//test/util:save_util",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:time_util",
    ],
)

cc_binary(
    name = "pselect_test",
    testonly = 1,
    srcs = ["pselect.cc"],
    linkstatic = 1,
    deps = [
        ":base_poll_test",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:signal_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "ptrace_test",
    testonly = 1,
    srcs = ["ptrace.cc"],
    linkstatic = 1,
    deps = [
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:capability_util",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "//test/util:logging",
        "//test/util:memory_util",
        "//test/util:multiprocess_util",
        "//test/util:platform_util",
        "//test/util:signal_util",
        "//test/util:temp_path",
        "//test/util:test_util",
        "//test/util:thread_util",
        "//test/util:time_util",
    ],
)

cc_binary(
    name = "pwrite64_test",
    testonly = 1,
    srcs = ["pwrite64.cc"],
    linkstatic = 1,
    deps = [
        gtest,
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "pwritev2_test",
    testonly = 1,
    srcs = [
        "pwritev2.cc",
    ],
    linkstatic = 1,
    deps = [
        ":file_base",
        "//test/util:file_descriptor",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "raw_socket_hdrincl_test",
    testonly = 1,
    srcs = ["raw_socket_hdrincl.cc"],
    linkstatic = 1,
    deps = [
        ":unix_domain_socket_test_util",
        "//test/util:capability_util",
        "//test/util:file_descriptor",
        "//test/util:socket_util",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/base:endian",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "raw_socket_test",
    testonly = 1,
    srcs = ["raw_socket.cc"],
    defines = select_system(),
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        ":unix_domain_socket_test_util",
        "//test/util:capability_util",
        "//test/util:file_descriptor",
        "//test/util:socket_util",
        "@com_google_absl//absl/base:core_headers",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "raw_socket_icmp_test",
    testonly = 1,
    srcs = ["raw_socket_icmp.cc"],
    linkstatic = 1,
    deps = [
        ":unix_domain_socket_test_util",
        "//test/util:capability_util",
        "//test/util:file_descriptor",
        "//test/util:socket_util",
        "@com_google_absl//absl/base:core_headers",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "read_test",
    testonly = 1,
    srcs = ["read.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "@com_google_absl//absl/base:core_headers",
        gtest,
        "//test/util:cleanup",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "readahead_test",
    testonly = 1,
    srcs = ["readahead.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "//test/util:socket_util",
        gtest,
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "readv_test",
    testonly = 1,
    srcs = [
        "file_base.h",
        "readv.cc",
        "readv_common.cc",
        "readv_common.h",
    ],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:timer_util",
    ],
)

cc_binary(
    name = "readv_socket_test",
    testonly = 1,
    srcs = [
        "readv_common.cc",
        "readv_common.h",
        "readv_socket.cc",
    ],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "rename_test",
    testonly = 1,
    srcs = ["rename.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:cleanup",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "rlimits_test",
    testonly = 1,
    srcs = ["rlimits.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "rseq_test",
    testonly = 1,
    srcs = ["rseq.cc"],
    data = ["//test/syscalls/linux/rseq"],
    linkstatic = 1,
    deps = [
        "//test/syscalls/linux/rseq:lib",
        gtest,
        "//test/util:logging",
        "//test/util:multiprocess_util",
        "//test/util:posix_error",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "rtsignal_test",
    testonly = 1,
    srcs = ["rtsignal.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:cleanup",
        gtest,
        "//test/util:logging",
        "//test/util:posix_error",
        "//test/util:signal_util",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "sched_test",
    testonly = 1,
    srcs = ["sched.cc"],
    linkstatic = 1,
    deps = [
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "sched_yield_test",
    testonly = 1,
    srcs = ["sched_yield.cc"],
    linkstatic = 1,
    deps = [
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "seccomp_test",
    testonly = 1,
    srcs = ["seccomp.cc"],
    linkstatic = 1,
    deps = [
        "@com_google_absl//absl/base:core_headers",
        gtest,
        "//test/util:logging",
        "//test/util:memory_util",
        "//test/util:multiprocess_util",
        "//test/util:posix_error",
        "//test/util:proc_util",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "select_test",
    testonly = 1,
    srcs = ["select.cc"],
    linkstatic = 1,
    deps = [
        ":base_poll_test",
        "//test/util:file_descriptor",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:multiprocess_util",
        "//test/util:posix_error",
        "//test/util:rlimit_util",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "sendfile_test",
    testonly = 1,
    srcs = ["sendfile.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:eventfd_util",
        "//test/util:file_descriptor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:signal_util",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
        "//test/util:timer_util",
    ],
)

cc_binary(
    name = "sendfile_socket_test",
    testonly = 1,
    srcs = ["sendfile_socket.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "//test/util:socket_util",
        "@com_google_absl//absl/strings",
        gtest,
        ":ip_socket_test_util",
        ":unix_domain_socket_test_util",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
        "//test/util:timer_util",
    ],
)

cc_binary(
    name = "setgid_test",
    testonly = 1,
    srcs = ["setgid.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:cleanup",
        "//test/util:fs_util",
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/strings",
        gtest,
    ],
)

cc_binary(
    name = "splice_test",
    testonly = 1,
    srcs = ["splice.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:signal_util",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
        "//test/util:timer_util",
    ],
)

cc_binary(
    name = "sigaction_test",
    testonly = 1,
    srcs = ["sigaction.cc"],
    linkstatic = 1,
    deps = [
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "sigaltstack_test",
    testonly = 1,
    srcs = ["sigaltstack.cc"],
    data = [
        ":sigaltstack_check",
    ],
    linkstatic = 1,
    deps = [
        "//test/util:cleanup",
        "//test/util:fs_util",
        gtest,
        "//test/util:multiprocess_util",
        "//test/util:posix_error",
        "//test/util:signal_util",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "sigreturn_test",
    testonly = 1,
    srcs = select_arch(
        amd64 = ["sigreturn_amd64.cc"],
        arm64 = ["sigreturn_arm64.cc"],
    ),
    linkstatic = 1,
    deps = [
        gtest,
        "//test/util:logging",
        "//test/util:signal_util",
        "//test/util:test_util",
        "//test/util:timer_util",
    ] + select_arch(
        amd64 = [],
        arm64 = ["//test/util:test_main"],
    ),
)

cc_binary(
    name = "signalfd_test",
    testonly = 1,
    srcs = ["signalfd.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "@com_google_absl//absl/synchronization",
        gtest,
        "//test/util:logging",
        "//test/util:posix_error",
        "//test/util:signal_util",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "sigprocmask_test",
    testonly = 1,
    srcs = ["sigprocmask.cc"],
    linkstatic = 1,
    deps = [
        gtest,
        "//test/util:signal_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "sigstop_test",
    testonly = 1,
    srcs = ["sigstop.cc"],
    linkstatic = 1,
    deps = [
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:multiprocess_util",
        "//test/util:posix_error",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "sigtimedwait_test",
    testonly = 1,
    srcs = ["sigtimedwait.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:logging",
        "//test/util:signal_util",
        "//test/util:test_util",
        "//test/util:thread_util",
        "//test/util:timer_util",
    ],
)

cc_library(
    name = "socket_generic_test_cases",
    testonly = 1,
    srcs = [
        "socket_generic_test_cases.cc",
    ],
    hdrs = [
        "socket_generic.h",
    ],
    deps = [
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        gtest,
        "//test/util:capability_util",
        "//test/util:test_util",
    ],
    alwayslink = 1,
)

cc_binary(
    name = "socket_stress_test",
    testonly = 1,
    srcs = [
        "socket_generic_stress.cc",
    ],
    linkstatic = 1,
    deps = [
        gtest,
        ":ip_socket_test_util",
        "//test/util:file_descriptor",
        "//test/util:socket_util",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
    ],
)

cc_library(
    name = "socket_unix_dgram_test_cases",
    testonly = 1,
    srcs = ["socket_unix_dgram.cc"],
    hdrs = ["socket_unix_dgram.h"],
    deps = [
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:test_util",
    ],
    alwayslink = 1,
)

cc_library(
    name = "socket_unix_seqpacket_test_cases",
    testonly = 1,
    srcs = ["socket_unix_seqpacket.cc"],
    hdrs = ["socket_unix_seqpacket.h"],
    deps = [
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:test_util",
    ],
    alwayslink = 1,
)

cc_library(
    name = "socket_ip_tcp_generic_test_cases",
    testonly = 1,
    srcs = [
        "socket_ip_tcp_generic.cc",
    ],
    hdrs = [
        "socket_ip_tcp_generic.h",
    ],
    deps = [
        "//test/util:socket_util",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:temp_path",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
    alwayslink = 1,
)

cc_library(
    name = "socket_non_blocking_test_cases",
    testonly = 1,
    srcs = [
        "socket_non_blocking.cc",
    ],
    hdrs = [
        "socket_non_blocking.h",
    ],
    deps = [
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_util",
    ],
    alwayslink = 1,
)

cc_library(
    name = "socket_unix_non_stream_test_cases",
    testonly = 1,
    srcs = [
        "socket_unix_non_stream.cc",
    ],
    hdrs = [
        "socket_unix_non_stream.h",
    ],
    deps = [
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        gtest,
        "//test/util:memory_util",
        "//test/util:test_util",
    ],
    alwayslink = 1,
)

cc_library(
    name = "socket_non_stream_test_cases",
    testonly = 1,
    srcs = [
        "socket_non_stream.cc",
    ],
    hdrs = [
        "socket_non_stream.h",
    ],
    deps = [
        ":ip_socket_test_util",
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_util",
    ],
    alwayslink = 1,
)

cc_library(
    name = "socket_ip_udp_test_cases",
    testonly = 1,
    srcs = [
        "socket_ip_udp_generic.cc",
    ],
    hdrs = [
        "socket_ip_udp_generic.h",
    ],
    deps = [
        ":ip_socket_test_util",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_util",
    ],
    alwayslink = 1,
)

cc_library(
    name = "socket_ipv4_datagram_based_socket_unbound_test_cases",
    testonly = 1,
    srcs = [
        "socket_ipv4_datagram_based_socket_unbound.cc",
    ],
    hdrs = [
        "socket_ipv4_datagram_based_socket_unbound.h",
    ],
    deps = [
        ":ip_socket_test_util",
        "//test/util:capability_util",
        "//test/util:socket_util",
        gtest,
    ],
    alwayslink = 1,
)

cc_library(
    name = "socket_ipv4_udp_unbound_test_cases",
    testonly = 1,
    srcs = [
        "socket_ipv4_udp_unbound.cc",
    ],
    hdrs = [
        "socket_ipv4_udp_unbound.h",
    ],
    deps = [
        ":ip_socket_test_util",
        "//test/util:socket_util",
        "@com_google_absl//absl/memory",
        gtest,
    ],
    alwayslink = 1,
)

cc_library(
    name = "socket_ipv6_udp_unbound_test_cases",
    testonly = 1,
    srcs = [
        "socket_ipv6_udp_unbound.cc",
    ],
    hdrs = [
        "socket_ipv6_udp_unbound.h",
    ],
    deps = [
        ":ip_socket_test_util",
        "//test/util:socket_util",
        "@com_google_absl//absl/memory",
        gtest,
        "//test/util:posix_error",
        "//test/util:save_util",
        "//test/util:test_util",
    ],
    alwayslink = 1,
)

cc_library(
    name = "socket_ipv4_udp_unbound_netlink_test_cases",
    testonly = 1,
    srcs = [
        "socket_ipv4_udp_unbound_netlink.cc",
    ],
    hdrs = [
        "socket_ipv4_udp_unbound_netlink.h",
    ],
    deps = [
        ":socket_netlink_route_util",
        "//test/util:capability_util",
        "//test/util:cleanup",
        "//test/util:socket_util",
        gtest,
    ],
    alwayslink = 1,
)

cc_library(
    name = "socket_ipv6_udp_unbound_netlink_test_cases",
    testonly = 1,
    srcs = [
        "socket_ipv6_udp_unbound_netlink.cc",
    ],
    hdrs = [
        "socket_ipv6_udp_unbound_netlink.h",
    ],
    deps = [
        ":socket_netlink_route_util",
        "//test/util:capability_util",
        "//test/util:socket_util",
        gtest,
    ],
    alwayslink = 1,
)

cc_library(
    name = "socket_ip_udp_unbound_external_networking",
    testonly = 1,
    hdrs = [
        "socket_ip_udp_unbound_external_networking.h",
    ],
    deps = [
        ":ip_socket_test_util",
    ],
    alwayslink = 1,
)

cc_library(
    name = "socket_ipv4_udp_unbound_external_networking_test_cases",
    testonly = 1,
    srcs = [
        "socket_ipv4_udp_unbound_external_networking.cc",
    ],
    hdrs = [
        "socket_ipv4_udp_unbound_external_networking.h",
    ],
    deps = [
        ":socket_ip_udp_unbound_external_networking",
        "//test/util:socket_util",
        "//test/util:test_util",
        "@com_google_absl//absl/cleanup",
        gtest,
    ],
    alwayslink = 1,
)

cc_library(
    name = "socket_ipv6_udp_unbound_external_networking_test_cases",
    testonly = 1,
    srcs = [
        "socket_ipv6_udp_unbound_external_networking.cc",
    ],
    hdrs = [
        "socket_ipv6_udp_unbound_external_networking.h",
    ],
    deps = [
        ":socket_ip_udp_unbound_external_networking",
        gtest,
    ],
    alwayslink = 1,
)

cc_binary(
    name = "socket_abstract_test",
    testonly = 1,
    srcs = [
        "socket_abstract.cc",
    ],
    linkstatic = 1,
    deps = [
        ":socket_generic_test_cases",
        ":socket_unix_cmsg_test_cases",
        ":socket_unix_test_cases",
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_abstract_non_blocking_test",
    testonly = 1,
    srcs = [
        "socket_unix_abstract_nonblock.cc",
    ],
    linkstatic = 1,
    deps = [
        ":socket_non_blocking_test_cases",
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_unix_dgram_local_test",
    testonly = 1,
    srcs = ["socket_unix_dgram_local.cc"],
    linkstatic = 1,
    deps = [
        ":socket_non_stream_test_cases",
        ":socket_unix_dgram_test_cases",
        ":socket_unix_non_stream_test_cases",
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_unix_dgram_non_blocking_test",
    testonly = 1,
    srcs = ["socket_unix_dgram_non_blocking.cc"],
    linkstatic = 1,
    deps = [
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_unix_seqpacket_local_test",
    testonly = 1,
    srcs = [
        "socket_unix_seqpacket_local.cc",
    ],
    linkstatic = 1,
    deps = [
        ":socket_non_stream_test_cases",
        ":socket_unix_non_stream_test_cases",
        ":socket_unix_seqpacket_test_cases",
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_unix_stream_test",
    testonly = 1,
    srcs = ["socket_unix_stream.cc"],
    linkstatic = 1,
    deps = [
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_ip_tcp_generic_loopback_test",
    testonly = 1,
    srcs = [
        "socket_ip_tcp_generic_loopback.cc",
    ],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        ":socket_ip_tcp_generic_test_cases",
        "//test/util:socket_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_ip_tcp_udp_generic_loopback_test",
    testonly = 1,
    srcs = [
        "socket_ip_tcp_udp_generic.cc",
    ],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_ip_tcp_loopback_test",
    testonly = 1,
    srcs = [
        "socket_ip_tcp_loopback.cc",
    ],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        ":socket_generic_test_cases",
        "//test/util:socket_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_ip_tcp_loopback_non_blocking_test",
    testonly = 1,
    srcs = [
        "socket_ip_tcp_loopback_nonblock.cc",
    ],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        ":socket_non_blocking_test_cases",
        "//test/util:socket_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_ip_udp_loopback_test",
    testonly = 1,
    srcs = [
        "socket_ip_udp_loopback.cc",
    ],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        ":socket_generic_test_cases",
        ":socket_ip_udp_test_cases",
        ":socket_non_stream_test_cases",
        "//test/util:socket_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_ipv4_udp_unbound_external_networking_test",
    testonly = 1,
    srcs = [
        "socket_ipv4_udp_unbound_external_networking_test.cc",
    ],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        ":socket_ipv4_udp_unbound_external_networking_test_cases",
        "//test/util:socket_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_ipv6_udp_unbound_external_networking_test",
    testonly = 1,
    srcs = [
        "socket_ipv6_udp_unbound_external_networking_test.cc",
    ],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        ":socket_ipv6_udp_unbound_external_networking_test_cases",
        "//test/util:socket_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_bind_to_device_test",
    testonly = 1,
    srcs = [
        "socket_bind_to_device.cc",
    ],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        ":socket_bind_to_device_util",
        "//test/util:capability_util",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "socket_bind_to_device_sequence_test",
    testonly = 1,
    srcs = [
        "socket_bind_to_device_sequence.cc",
    ],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        ":socket_bind_to_device_util",
        "//test/util:capability_util",
        "//test/util:socket_util",
        "@com_google_absl//absl/container:node_hash_map",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "socket_bind_to_device_distribution_test",
    testonly = 1,
    srcs = [
        "socket_bind_to_device_distribution.cc",
    ],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        ":socket_bind_to_device_util",
        "//test/util:capability_util",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "socket_ip_udp_loopback_non_blocking_test",
    testonly = 1,
    srcs = [
        "socket_ip_udp_loopback_nonblock.cc",
    ],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        ":socket_non_blocking_test_cases",
        "//test/util:socket_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_ipv4_udp_unbound_loopback_test",
    testonly = 1,
    srcs = [
        "socket_ipv4_udp_unbound_loopback.cc",
    ],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        ":socket_ipv4_udp_unbound_test_cases",
        "//test/util:test_main",
    ],
)

cc_binary(
    name = "socket_ipv4_datagram_based_socket_unbound_loopback_test",
    testonly = 1,
    srcs = [
        "socket_ipv4_datagram_based_socket_unbound_loopback.cc",
    ],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        ":socket_ipv4_datagram_based_socket_unbound_test_cases",
        "//test/util:test_main",
    ],
)

cc_binary(
    name = "socket_ipv6_udp_unbound_loopback_test",
    testonly = 1,
    srcs = [
        "socket_ipv6_udp_unbound_loopback.cc",
    ],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        ":socket_ipv6_udp_unbound_test_cases",
        "//test/util:socket_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_ipv4_udp_unbound_loopback_nogotsan_test",
    testonly = 1,
    srcs = [
        "socket_ipv4_udp_unbound_loopback_nogotsan.cc",
    ],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
        "@com_google_absl//absl/memory",
    ],
)

cc_binary(
    name = "socket_ipv4_udp_unbound_loopback_netlink_test",
    testonly = 1,
    srcs = [
        "socket_ipv4_udp_unbound_loopback_netlink.cc",
    ],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        ":socket_ipv4_udp_unbound_netlink_test_cases",
        "//test/util:socket_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_ipv6_udp_unbound_loopback_netlink_test",
    testonly = 1,
    srcs = [
        "socket_ipv6_udp_unbound_loopback_netlink.cc",
    ],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        ":socket_ipv6_udp_unbound_netlink_test_cases",
        "//test/util:socket_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_ip_unbound_test",
    testonly = 1,
    srcs = [
        "socket_ip_unbound.cc",
    ],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_ip_unbound_netlink_test",
    testonly = 1,
    srcs = [
        "socket_ip_unbound_netlink.cc",
    ],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        ":socket_netlink_route_util",
        "//test/util:capability_util",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_domain_test",
    testonly = 1,
    srcs = [
        "socket_unix_domain.cc",
    ],
    linkstatic = 1,
    deps = [
        ":socket_generic_test_cases",
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_domain_non_blocking_test",
    testonly = 1,
    srcs = [
        "socket_unix_pair_nonblock.cc",
    ],
    linkstatic = 1,
    deps = [
        ":socket_non_blocking_test_cases",
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_filesystem_test",
    testonly = 1,
    srcs = [
        "socket_filesystem.cc",
    ],
    linkstatic = 1,
    deps = [
        ":socket_generic_test_cases",
        ":socket_unix_cmsg_test_cases",
        ":socket_unix_test_cases",
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_filesystem_non_blocking_test",
    testonly = 1,
    srcs = [
        "socket_unix_filesystem_nonblock.cc",
    ],
    linkstatic = 1,
    deps = [
        ":socket_non_blocking_test_cases",
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_library(
    name = "socket_inet_loopback_test_params",
    testonly = 1,
    hdrs = ["socket_inet_loopback_test_params.h"],
    deps = [
        "//test/util:socket_util",
        gtest,
    ],
)

cc_binary(
    name = "socket_inet_loopback_test",
    testonly = 1,
    srcs = ["socket_inet_loopback.cc"],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        ":socket_inet_loopback_test_params",
        "//test/util:file_descriptor",
        "//test/util:socket_util",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:posix_error",
        "//test/util:save_util",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "socket_inet_loopback_nogotsan_test",
    testonly = 1,
    srcs = ["socket_inet_loopback_nogotsan.cc"],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        ":socket_inet_loopback_test_params",
        "//test/util:file_descriptor",
        "//test/util:socket_util",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:posix_error",
        "//test/util:save_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_inet_loopback_isolated_test",
    testonly = 1,
    srcs = ["socket_inet_loopback_isolated.cc"],
    linkstatic = 1,
    deps = [
        ":socket_inet_loopback_test_params",
        ":socket_netlink_util",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
        "@com_google_absl//absl/time",
    ],
)

cc_binary(
    name = "socket_netlink_test",
    testonly = 1,
    srcs = ["socket_netlink.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_netlink_route_test",
    testonly = 1,
    srcs = ["socket_netlink_route.cc"],
    linkstatic = 1,
    deps = [
        ":socket_netlink_route_util",
        ":socket_netlink_util",
        "//test/util:capability_util",
        "//test/util:cleanup",
        "//test/util:file_descriptor",
        "//test/util:socket_util",
        "@com_google_absl//absl/strings:str_format",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_netlink_uevent_test",
    testonly = 1,
    srcs = ["socket_netlink_uevent.cc"],
    linkstatic = 1,
    deps = [
        ":socket_netlink_util",
        "//test/util:file_descriptor",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

# These socket tests are in a library because the test cases are shared
# across several test build targets.
cc_library(
    name = "socket_stream_test_cases",
    testonly = 1,
    srcs = [
        "socket_stream.cc",
    ],
    hdrs = [
        "socket_stream.h",
    ],
    deps = [
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:test_util",
    ],
    alwayslink = 1,
)

cc_library(
    name = "socket_blocking_test_cases",
    testonly = 1,
    srcs = [
        "socket_blocking.cc",
    ],
    hdrs = [
        "socket_blocking.h",
    ],
    deps = [
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:test_util",
        "//test/util:thread_util",
        "//test/util:timer_util",
    ],
    alwayslink = 1,
)

cc_library(
    name = "socket_unix_test_cases",
    testonly = 1,
    srcs = [
        "socket_unix.cc",
    ],
    hdrs = [
        "socket_unix.h",
    ],
    deps = [
        ":unix_domain_socket_test_util",
        "//test/util:file_descriptor",
        "//test/util:memory_util",
        "//test/util:socket_util",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:temp_path",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
    alwayslink = 1,
)

cc_library(
    name = "socket_unix_cmsg_test_cases",
    testonly = 1,
    srcs = [
        "socket_unix_cmsg.cc",
    ],
    hdrs = [
        "socket_unix_cmsg.h",
    ],
    deps = [
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
    alwayslink = 1,
)

cc_library(
    name = "socket_stream_blocking_test_cases",
    testonly = 1,
    srcs = [
        "socket_stream_blocking.cc",
    ],
    hdrs = [
        "socket_stream_blocking.h",
    ],
    deps = [
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:test_util",
        "//test/util:thread_util",
        "//test/util:timer_util",
    ],
    alwayslink = 1,
)

cc_library(
    name = "socket_stream_nonblocking_test_cases",
    testonly = 1,
    srcs = [
        "socket_stream_nonblock.cc",
    ],
    hdrs = [
        "socket_stream_nonblock.h",
    ],
    deps = [
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_util",
    ],
    alwayslink = 1,
)

cc_library(
    name = "socket_non_stream_blocking_test_cases",
    testonly = 1,
    srcs = [
        "socket_non_stream_blocking.cc",
    ],
    hdrs = [
        "socket_non_stream_blocking.h",
    ],
    deps = [
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
    alwayslink = 1,
)

cc_library(
    name = "socket_bind_to_device_util",
    testonly = 1,
    srcs = [
        "socket_bind_to_device_util.cc",
    ],
    hdrs = [
        "socket_bind_to_device_util.h",
    ],
    deps = [
        "//test/util:test_util",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
    alwayslink = 1,
)

cc_binary(
    name = "socket_stream_local_test",
    testonly = 1,
    srcs = [
        "socket_unix_stream_local.cc",
    ],
    linkstatic = 1,
    deps = [
        ":socket_stream_test_cases",
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_stream_blocking_local_test",
    testonly = 1,
    srcs = [
        "socket_unix_stream_blocking_local.cc",
    ],
    linkstatic = 1,
    deps = [
        ":socket_stream_blocking_test_cases",
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_stream_blocking_tcp_test",
    testonly = 1,
    srcs = [
        "socket_ip_tcp_loopback_blocking.cc",
    ],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        ":socket_stream_blocking_test_cases",
        "//test/util:socket_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_stream_nonblock_local_test",
    testonly = 1,
    srcs = [
        "socket_unix_stream_nonblock_local.cc",
    ],
    linkstatic = 1,
    deps = [
        ":socket_stream_nonblocking_test_cases",
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_unix_unbound_dgram_test",
    testonly = 1,
    srcs = ["socket_unix_unbound_dgram.cc"],
    linkstatic = 1,
    deps = [
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_unix_unbound_abstract_test",
    testonly = 1,
    srcs = ["socket_unix_unbound_abstract.cc"],
    linkstatic = 1,
    deps = [
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_unix_unbound_filesystem_test",
    testonly = 1,
    srcs = ["socket_unix_unbound_filesystem.cc"],
    linkstatic = 1,
    deps = [
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        gtest,
        "//test/util:file_descriptor",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_blocking_local_test",
    testonly = 1,
    srcs = [
        "socket_unix_blocking_local.cc",
    ],
    linkstatic = 1,
    deps = [
        ":socket_blocking_test_cases",
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_blocking_ip_test",
    testonly = 1,
    srcs = [
        "socket_ip_loopback_blocking.cc",
    ],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        ":socket_blocking_test_cases",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_non_stream_blocking_local_test",
    testonly = 1,
    srcs = [
        "socket_unix_non_stream_blocking_local.cc",
    ],
    linkstatic = 1,
    deps = [
        ":socket_non_stream_blocking_test_cases",
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_non_stream_blocking_udp_test",
    testonly = 1,
    srcs = [
        "socket_ip_udp_loopback_blocking.cc",
    ],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        ":socket_non_stream_blocking_test_cases",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_unix_pair_test",
    testonly = 1,
    srcs = [
        "socket_unix_pair.cc",
    ],
    linkstatic = 1,
    deps = [
        ":socket_unix_cmsg_test_cases",
        ":socket_unix_test_cases",
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_unix_unbound_seqpacket_test",
    testonly = 1,
    srcs = ["socket_unix_unbound_seqpacket.cc"],
    linkstatic = 1,
    deps = [
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_unix_unbound_stream_test",
    testonly = 1,
    srcs = ["socket_unix_unbound_stream.cc"],
    linkstatic = 1,
    deps = [
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "socket_netdevice_test",
    testonly = 1,
    srcs = ["socket_netdevice.cc"],
    linkstatic = 1,
    deps = [
        ":socket_netlink_util",
        "//test/util:file_descriptor",
        "//test/util:socket_util",
        "@com_google_absl//absl/base:endian",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "stat_test",
    testonly = 1,
    srcs = [
        "file_base.h",
        "stat.cc",
    ],
    linkstatic = 1,
    deps = [
        "//test/util:cleanup",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:posix_error",
        "//test/util:save_util",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "stat_times_test",
    testonly = 1,
    srcs = ["stat_times.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "statfs_test",
    testonly = 1,
    srcs = [
        "file_base.h",
        "statfs.cc",
    ],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "symlink_test",
    testonly = 1,
    srcs = ["symlink.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "verity_symlink_test",
    testonly = 1,
    srcs = ["verity_symlink.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        gtest,
        "//test/util:fs_util",
        "//test/util:mount_util",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:verity_util",
    ],
)

cc_binary(
    name = "sync_test",
    testonly = 1,
    # Android does not support syncfs in r22.
    srcs = select_system(linux = ["sync.cc"]),
    linkstatic = 1,
    deps = [
        gtest,
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "sysinfo_test",
    testonly = 1,
    srcs = ["sysinfo.cc"],
    linkstatic = 1,
    deps = [
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "syslog_test",
    testonly = 1,
    srcs = ["syslog.cc"],
    linkstatic = 1,
    deps = [
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "sysret_test",
    testonly = 1,
    srcs = ["sysret.cc"],
    linkstatic = 1,
    deps = [
        gtest,
        "//test/util:logging",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "tcp_socket_test",
    testonly = 1,
    srcs = ["tcp_socket.cc"],
    defines = select_system(),
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "//test/util:socket_util",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:posix_error",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "tgkill_test",
    testonly = 1,
    srcs = ["tgkill.cc"],
    linkstatic = 1,
    deps = [
        gtest,
        "//test/util:signal_util",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "time_test",
    testonly = 1,
    srcs = ["time.cc"],
    linkstatic = 1,
    deps = [
        gtest,
        "//test/util:proc_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "timerfd_test",
    testonly = 1,
    srcs = ["timerfd.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "//test/util:posix_error",
        "//test/util:test_main",
        "//test/util:test_util",
        "@com_google_absl//absl/time",
    ],
)

cc_binary(
    name = "timers_test",
    testonly = 1,
    srcs = ["timers.cc"],
    linkstatic = 1,
    deps = [
        gbenchmark,
        gtest,
        "//test/util:cleanup",
        "//test/util:logging",
        "//test/util:multiprocess_util",
        "//test/util:posix_error",
        "//test/util:signal_util",
        "//test/util:test_util",
        "//test/util:thread_util",
        "//test/util:timer_util",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/time",
    ],
)

cc_binary(
    name = "tkill_test",
    testonly = 1,
    srcs = ["tkill.cc"],
    linkstatic = 1,
    deps = [
        gtest,
        "//test/util:logging",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "truncate_test",
    testonly = 1,
    srcs = ["truncate.cc"],
    linkstatic = 1,
    deps = [
        ":file_base",
        "//test/util:capability_util",
        "//test/util:cleanup",
        "//test/util:file_descriptor",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "tuntap_test",
    testonly = 1,
    srcs = ["tuntap.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:socket_util",
        gtest,
        ":socket_netlink_route_util",
        "//test/util:capability_util",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "//test/util:posix_error",
        "//test/util:test_main",
        "//test/util:test_util",
        "@com_google_absl//absl/strings",
    ],
)

cc_binary(
    name = "tuntap_hostinet_test",
    testonly = 1,
    srcs = ["tuntap_hostinet.cc"],
    linkstatic = 1,
    deps = [
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "udp_socket_test",
    testonly = 1,
    srcs = ["udp_socket.cc"],
    defines = select_system(),
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        ":unix_domain_socket_test_util",
        "//test/util:socket_util",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:file_descriptor",
        "//test/util:posix_error",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "udp_bind_test",
    testonly = 1,
    srcs = ["udp_bind.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "//test/util:socket_util",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "uidgid_test",
    testonly = 1,
    srcs = ["uidgid.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:cleanup",
        "//test/util:multiprocess_util",
        "//test/util:posix_error",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
        "//test/util:uid_util",
    ],
)

cc_binary(
    name = "uname_test",
    testonly = 1,
    srcs = ["uname.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "unlink_test",
    testonly = 1,
    srcs = ["unlink.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "unshare_test",
    testonly = 1,
    srcs = ["unshare.cc"],
    linkstatic = 1,
    deps = [
        "@com_google_absl//absl/synchronization",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "utimes_test",
    testonly = 1,
    # Android does not support futimesat in r22.
    srcs = select_system(linux = ["utimes.cc"]),
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "@com_google_absl//absl/time",
    ],
)

cc_binary(
    name = "vdso_test",
    testonly = 1,
    srcs = ["vdso.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:fs_util",
        gtest,
        "//test/util:posix_error",
        "//test/util:proc_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "vfork_test",
    testonly = 1,
    srcs = ["vfork.cc"],
    linkstatic = 1,
    deps = [
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:logging",
        "//test/util:multiprocess_util",
        "//test/util:test_util",
        "//test/util:time_util",
    ],
)

cc_binary(
    name = "wait_test",
    testonly = 1,
    srcs = ["wait.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:cleanup",
        "//test/util:file_descriptor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:logging",
        "//test/util:multiprocess_util",
        "//test/util:posix_error",
        "//test/util:signal_util",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
        "//test/util:time_util",
    ],
)

cc_binary(
    name = "write_test",
    testonly = 1,
    srcs = ["write.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:cleanup",
        "@com_google_absl//absl/base:core_headers",
        gtest,
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "memory_accounting_test",
    testonly = 1,
    srcs = ["memory_accounting.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:fs_util",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        gtest,
        "//test/util:posix_error",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "network_namespace_test",
    testonly = 1,
    srcs = ["network_namespace.cc"],
    linkstatic = 1,
    deps = [
        gtest,
        ":ip_socket_test_util",
        "//test/util:capability_util",
        "//test/util:test_main",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "mq_test",
    testonly = 1,
    srcs = ["mq.cc"],
    linkopts = [
        "-lrt",
    ],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:cleanup",
        "//test/util:fs_util",
        "//test/util:mount_util",
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "semaphore_test",
    testonly = 1,
    # Android does not support XSI semaphores in r22.
    srcs = select_system(linux = ["semaphore.cc"]),
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "shm_test",
    testonly = 1,
    srcs = ["shm.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:multiprocess_util",
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "@com_google_absl//absl/time",
    ],
)

cc_binary(
    name = "msgqueue_test",
    testonly = 1,
    srcs = ["msgqueue.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:signal_util",
        "//test/util:temp_path",
        "//test/util:test_util",
        "//test/util:thread_util",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
    ],
)

cc_binary(
    name = "fadvise64_test",
    testonly = 1,
    srcs = ["fadvise64.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        gtest,
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "vdso_clock_gettime_test",
    testonly = 1,
    srcs = ["vdso_clock_gettime.cc"],
    linkstatic = 1,
    deps = [
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "vsyscall_test",
    testonly = 1,
    srcs = ["vsyscall.cc"],
    linkstatic = 1,
    deps = [
        gtest,
        "//test/util:proc_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "proc_net_unix_test",
    testonly = 1,
    srcs = ["proc_net_unix.cc"],
    linkstatic = 1,
    deps = [
        ":unix_domain_socket_test_util",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        gtest,
        "//test/util:cleanup",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "memfd_test",
    testonly = 1,
    srcs = ["memfd.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        gtest,
        "//test/util:memory_util",
        "//test/util:multiprocess_util",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "proc_net_tcp_test",
    testonly = 1,
    srcs = ["proc_net_tcp.cc"],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        "//test/util:file_descriptor",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "proc_net_udp_test",
    testonly = 1,
    srcs = ["proc_net_udp.cc"],
    linkstatic = 1,
    deps = [
        ":ip_socket_test_util",
        "//test/util:file_descriptor",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "processes_test",
    testonly = 1,
    srcs = ["processes.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "xattr_test",
    testonly = 1,
    srcs = [
        "file_base.h",
        "xattr.cc",
    ],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "cgroup_test",
    testonly = 1,
    srcs = ["cgroup.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:capability_util",
        "//test/util:cgroup_util",
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "//test/util:mount_util",
        "@com_google_absl//absl/strings",
        gtest,
        "//test/util:cleanup",
        "//test/util:posix_error",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
    ],
)

cc_binary(
    name = "deleted_test",
    testonly = 1,
    srcs = ["deleted.cc"],
    linkstatic = 1,
    deps = [
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        gtest,
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)
