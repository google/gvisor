package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

cc_library(
    name = "capability_util",
    testonly = 1,
    srcs = ["capability_util.cc"],
    hdrs = ["capability_util.h"],
    deps = [
        ":cleanup",
        ":memory_util",
        ":posix_error",
        ":save_util",
        ":test_util",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "eventfd_util",
    testonly = 1,
    hdrs = ["eventfd_util.h"],
    deps = [
        ":file_descriptor",
        ":posix_error",
        ":save_util",
    ],
)

cc_library(
    name = "file_descriptor",
    testonly = 1,
    hdrs = ["file_descriptor.h"],
    deps = [
        ":logging",
        ":posix_error",
        ":save_util",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "proc_util",
    testonly = 1,
    srcs = ["proc_util.cc"],
    hdrs = ["proc_util.h"],
    deps = [
        ":fs_util",
        ":posix_error",
        ":test_util",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_test(
    name = "proc_util_test",
    size = "small",
    srcs = ["proc_util_test.cc"],
    deps = [
        ":proc_util",
        ":test_main",
        ":test_util",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "cleanup",
    testonly = 1,
    hdrs = ["cleanup.h"],
)

cc_library(
    name = "fs_util",
    testonly = 1,
    srcs = ["fs_util.cc"],
    hdrs = ["fs_util.h"],
    deps = [
        ":cleanup",
        ":file_descriptor",
        ":posix_error",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_test(
    name = "fs_util_test",
    size = "small",
    srcs = ["fs_util_test.cc"],
    deps = [
        ":fs_util",
        ":posix_error",
        ":temp_path",
        ":test_main",
        ":test_util",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "logging",
    testonly = 1,
    srcs = ["logging.cc"],
    hdrs = ["logging.h"],
)

cc_library(
    name = "memory_util",
    testonly = 1,
    hdrs = ["memory_util.h"],
    deps = [
        ":logging",
        ":posix_error",
        ":save_util",
        ":test_util",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_library(
    name = "mount_util",
    testonly = 1,
    hdrs = ["mount_util.h"],
    deps = [
        ":cleanup",
        ":posix_error",
        ":test_util",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "save_util",
    testonly = 1,
    srcs = ["save_util.cc"],
    hdrs = ["save_util.h"],
)

cc_library(
    name = "multiprocess_util",
    testonly = 1,
    srcs = ["multiprocess_util.cc"],
    hdrs = ["multiprocess_util.h"],
    deps = [
        ":cleanup",
        ":file_descriptor",
        ":posix_error",
        ":save_util",
        ":test_util",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "posix_error",
    testonly = 1,
    srcs = ["posix_error.cc"],
    hdrs = ["posix_error.h"],
    deps = [
        ":logging",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:variant",
        "@com_google_googletest//:gtest",
    ],
)

cc_test(
    name = "posix_error_test",
    size = "small",
    srcs = ["posix_error_test.cc"],
    deps = [
        ":posix_error",
        ":test_main",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "signal_util",
    testonly = 1,
    srcs = ["signal_util.cc"],
    hdrs = ["signal_util.h"],
    deps = [
        ":cleanup",
        ":posix_error",
        ":test_util",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "temp_path",
    testonly = 1,
    srcs = ["temp_path.cc"],
    hdrs = ["temp_path.h"],
    deps = [
        ":fs_util",
        ":posix_error",
        ":test_util",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "test_util",
    testonly = 1,
    srcs = ["test_util.cc"],
    hdrs = ["test_util.h"],
    deps = [
        ":fs_util",
        ":logging",
        ":posix_error",
        ":save_util",
        "@com_github_gflags_gflags//:gflags",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "thread_util",
    testonly = 1,
    hdrs = ["thread_util.h"],
    deps = [":logging"],
)

cc_library(
    name = "timer_util",
    testonly = 1,
    srcs = ["timer_util.cc"],
    hdrs = ["timer_util.h"],
    deps = [
        ":cleanup",
        ":logging",
        ":posix_error",
        ":test_util",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
    ],
)

cc_test(
    name = "test_util_test",
    size = "small",
    srcs = ["test_util_test.cc"],
    deps = [
        ":test_main",
        ":test_util",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "test_main",
    testonly = 1,
    srcs = ["test_main.cc"],
    deps = [":test_util"],
)

cc_library(
    name = "epoll_util",
    testonly = 1,
    srcs = ["epoll_util.cc"],
    hdrs = ["epoll_util.h"],
    deps = [
        ":file_descriptor",
        ":posix_error",
        ":save_util",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "rlimit_util",
    testonly = 1,
    srcs = ["rlimit_util.cc"],
    hdrs = ["rlimit_util.h"],
    deps = [
        ":cleanup",
        ":logging",
        ":posix_error",
        ":test_util",
    ],
)
