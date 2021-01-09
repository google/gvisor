"""Packaging rules."""

# N.B. We refer to pkg_deb_impl to avoid the macro, which cannot use select.
load("@rules_pkg//:pkg.bzl", _pkg_deb = "pkg_deb_impl", _pkg_tar = "pkg_tar")

pkg_deb = _pkg_deb
pkg_tar = _pkg_tar
