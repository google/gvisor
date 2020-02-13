"""Provides attributes common to many workload tests."""

load("//tools:defs.bzl", "py_requirement")

test_deps = [
    py_requirement("attrs", direct = False),
    py_requirement("atomicwrites", direct = False),
    py_requirement("more-itertools", direct = False),
    py_requirement("pathlib2", direct = False),
    py_requirement("pluggy", direct = False),
    py_requirement("py", direct = False),
    py_requirement("pytest"),
    py_requirement("six", direct = False),
]
