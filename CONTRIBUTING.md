# Contributing

Want to contribute? Great! First, read this page.

### Contributor License Agreement

Contributions to this project must be accompanied by a Contributor License
Agreement. You (or your employer) retain the copyright to your contribution;
this simply gives us permission to use and redistribute your contributions as
part of the project. Head over to <https://cla.developers.google.com/> to see
your current agreements on file or to sign a new one.

You generally only need to submit a CLA once, so if you've already submitted one
(even if it was for a different project), you probably don't need to do it
again.

### Using GOPATH

Some editors may require the code to be structured in a `GOPATH` directory tree.
In this case, you may use the `:gopath` target to generate a directory tree with
symlinks to the original source files.

```
bazel build :gopath
```

You can then set the `GOPATH` in your editor to `bazel-bin/gopath`.

If you use this mechanism, keep in mind that the generated tree is not the
canonical source. You will still need to build and test with `bazel`. New files
will need to be added to the appropriate `BUILD` files, and the `:gopath` target
will need to be re-run to generate appropriate symlinks in the `GOPATH`
directory tree.

### Coding Guidelines

All Go code should conform to the [Go style guidelines][gostyle]. C++ code
should conform to the [Google C++ Style Guide][cppstyle] and the guidelines
described for [tests][teststyle].

As a secure runtime, we need to maintain the safety of all of code included in
gVisor. The following rules help mitigate issues.

Definitions for the rules below:

`core`:

*   `//pkg/sentry/...`
*   Transitive dependencies in `//pkg/...`, `//third_party/...`.

`runsc`:

*   `//runsc/...`

Rules:

*   No cgo in `core` or `runsc`. The final binary must be a statically-linked
    pure Go binary.

*   Any files importing "unsafe" must have a name ending in `_unsafe.go`.

*   `core` may only depend on the following packages:

    *   Itself.
    *   Go standard library.
        *   Except (transitively) package "net" (this will result in a non-cgo
            binary). Use `//pkg/unet` instead.
    *   `@org_golang_x_sys//unix:go_default_library` (Go import
        `golang.org/x/sys/unix`).
    *   Generated Go protobuf packages.
    *   `@com_github_golang_protobuf//proto:go_default_library` (Go import
        `github.com/golang/protobuf/proto`).
    *   `@com_github_golang_protobuf//ptypes:go_default_library` (Go import
        `github.com/golang/protobuf/ptypes`).

*   `runsc` may only depend on the following packages:

    *   All packages allowed for `core`.
    *   `@com_github_google_subcommands//:go_default_library` (Go import
        `github.com/google/subcommands`).
    *   `@com_github_opencontainers_runtime_spec//specs_go:go_default_library`
        (Go import `github.com/opencontainers/runtime-spec/specs_go`).

### Code reviews

Code changes are accepted via [pull request][github].

When approved, the change will be submitted by a team member and automatically
merged into the repository.

### Bug IDs

Some TODOs and NOTEs sprinkled throughout the code have associated IDs of the
form `b/1234`. These correspond to bugs in our internal bug tracker. Eventually
these bugs will be moved to the GitHub Issues, but until then they can simply be
ignored.

### The small print

Contributions made by corporations are covered by a different agreement than the
one above, the
[Software Grant and Corporate Contributor License Agreement][gccla].

[cppstyle]: https://google.github.io/styleguide/cppguide.html
[gcla]: https://cla.developers.google.com/about/google-individual
[gccla]: https://cla.developers.google.com/about/google-corporate
[github]: https://github.com/google/gvisor/compare
[gostyle]: https://github.com/golang/go/wiki/CodeReviewComments
[teststyle]: ./test/
