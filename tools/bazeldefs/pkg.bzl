"""Packaging rules."""

load("@rules_pkg//pkg:pkg.bzl", _pkg_deb = "pkg_deb", _pkg_tar = "pkg_tar")

pkg_deb = _pkg_deb
pkg_tar = _pkg_tar
