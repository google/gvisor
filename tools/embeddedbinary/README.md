# embeddedbinary

`embeddedbinary` can embed a binary inside a Go binary, and provides functions
to execute it.

Embedded binaries are compressed to save on size. They require temporary disk
space to execute, but the disk space is automatically freed when the child
program exits.

## Usage

Use the `embedded_binary_go_library` rule defined in `defs.bzl`.

```build
load(".../defs.bzl", "embedded_binary_go_library")

# Declare a binary target:
go_binary(
    name = "my_binary",
    srcs = ["my_binary.go"],
)

# Generate a go_library rule that can execute the binary target:
embedded_binary_go_library(
    name = "my_library",
    binary = ":my_binary",
)
```

See `test/BUILD` under this directory for a full example.
