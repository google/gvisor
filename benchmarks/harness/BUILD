load("//tools:defs.bzl", "pkg_tar")
load("//tools:defs.bzl", "py_library", "py_requirement")

package(
    default_visibility = ["//benchmarks:__subpackages__"],
    licenses = ["notice"],
)

pkg_tar(
    name = "installers",
    srcs = [
        "//tools/installers:head",
        "//tools/installers:master",
        "//tools/installers:runsc",
    ],
    mode = "0755",
)

filegroup(
    name = "files",
    srcs = [
        ":installers",
    ],
)

py_library(
    name = "harness",
    srcs = ["__init__.py"],
    data = [
        ":files",
    ],
)

py_library(
    name = "benchmark_driver",
    srcs = ["benchmark_driver.py"],
    deps = [
        "//benchmarks/harness/machine_mocks",
        "//benchmarks/harness/machine_producers:machine_producer",
        "//benchmarks/suites",
    ],
)

py_library(
    name = "container",
    srcs = ["container.py"],
    deps = [
        "//benchmarks/workloads",
        py_requirement("asn1crypto", False),
        py_requirement("chardet", False),
        py_requirement("certifi", False),
        py_requirement("docker", True),
        py_requirement("docker-pycreds", False),
        py_requirement("idna", False),
        py_requirement("ptyprocess", False),
        py_requirement("requests", False),
        py_requirement("urllib3", False),
        py_requirement("websocket-client", False),
    ],
)

py_library(
    name = "machine",
    srcs = ["machine.py"],
    deps = [
        "//benchmarks/harness",
        "//benchmarks/harness:container",
        "//benchmarks/harness:ssh_connection",
        "//benchmarks/harness:tunnel_dispatcher",
        "//benchmarks/harness/machine_mocks",
        py_requirement("asn1crypto", False),
        py_requirement("chardet", False),
        py_requirement("certifi", False),
        py_requirement("docker", True),
        py_requirement("docker-pycreds", False),
        py_requirement("idna", False),
        py_requirement("ptyprocess", False),
        py_requirement("requests", False),
        py_requirement("six", False),
        py_requirement("urllib3", False),
        py_requirement("websocket-client", False),
    ],
)

py_library(
    name = "ssh_connection",
    srcs = ["ssh_connection.py"],
    deps = [
        "//benchmarks/harness",
        py_requirement("bcrypt", False),
        py_requirement("cffi", True),
        py_requirement("paramiko", True),
        py_requirement("cryptography", False),
    ],
)

py_library(
    name = "tunnel_dispatcher",
    srcs = ["tunnel_dispatcher.py"],
    deps = [
        py_requirement("asn1crypto", False),
        py_requirement("chardet", False),
        py_requirement("certifi", False),
        py_requirement("docker", True),
        py_requirement("docker-pycreds", False),
        py_requirement("idna", False),
        py_requirement("pexpect", True),
        py_requirement("ptyprocess", False),
        py_requirement("requests", False),
        py_requirement("urllib3", False),
        py_requirement("websocket-client", False),
    ],
)
