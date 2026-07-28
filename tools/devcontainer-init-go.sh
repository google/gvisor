#!/usr/bin/env bash

# Running `go version` ensures that the appropriate Go binaries are downloaded.
exec bazel run @io_bazel_rules_go//go version
