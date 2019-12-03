load("//benchmarks:defs.bzl", "py_library", "requirement")

package(
    default_visibility = ["//benchmarks:__subpackages__"],
    licenses = ["notice"],
)

py_library(
    name = "harness",
    srcs = ["__init__.py"],
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
        requirement("asn1crypto", False),
        requirement("chardet", False),
        requirement("certifi", False),
        requirement("docker", True),
        requirement("docker-pycreds", False),
        requirement("idna", False),
        requirement("ptyprocess", False),
        requirement("requests", False),
        requirement("urllib3", False),
        requirement("websocket-client", False),
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
        requirement("asn1crypto", False),
        requirement("chardet", False),
        requirement("certifi", False),
        requirement("docker", True),
        requirement("docker-pycreds", False),
        requirement("idna", False),
        requirement("ptyprocess", False),
        requirement("requests", False),
        requirement("urllib3", False),
        requirement("websocket-client", False),
    ],
)

py_library(
    name = "ssh_connection",
    srcs = ["ssh_connection.py"],
    deps = [
        "//benchmarks/harness",
        requirement("bcrypt", False),
        requirement("cffi", False),
        requirement("paramiko", True),
        requirement("cryptography", False),
    ],
)

py_library(
    name = "tunnel_dispatcher",
    srcs = ["tunnel_dispatcher.py"],
    deps = [
        requirement("asn1crypto", False),
        requirement("chardet", False),
        requirement("certifi", False),
        requirement("docker", True),
        requirement("docker-pycreds", False),
        requirement("idna", False),
        requirement("pexpect", True),
        requirement("ptyprocess", False),
        requirement("requests", False),
        requirement("urllib3", False),
        requirement("websocket-client", False),
    ],
)
