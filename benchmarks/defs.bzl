"""Provides python helper functions."""

load("@pydeps//:requirements.bzl", _requirement = "requirement")

def filter_deps(deps = None):
    if deps == None:
        deps = []
    return [dep for dep in deps if dep]

def py_library(deps = None, **kwargs):
    return native.py_library(deps = filter_deps(deps), **kwargs)

def py_test(deps = None, **kwargs):
    return native.py_test(deps = filter_deps(deps), **kwargs)

def requirement(name, direct = True):
    """ requirement returns the required dependency. """
    return _requirement(name)
