Want to contribute? Great! First, read this page.

### Before you contribute

Before we can use your code, you must sign the
[Google Individual Contributor License Agreement]
(https://cla.developers.google.com/about/google-individual)
(CLA), which you can do online. The CLA is necessary mainly because you own the
copyright to your changes, even after your contribution becomes part of our
codebase, so we need your permission to use and distribute your code. We also
need to be sure of various other things—for instance that you'll tell us if you
know that your code infringes on other people's patents. You don't have to sign
the CLA until after you've submitted your code for review and a member has
approved it, but you must do it before we can put your code into our codebase.
Before you start working on a larger contribution, you should get in touch with
us first through the issue tracker with your idea so that we can help out and
possibly guide you. Coordinating up front makes it much easier to avoid
frustration later on.

### Coding Guidelines
All code should conform to the [Go style guidelines][gostyle].

As a secure runtime, we need to maintain the safety of all of code included in
gVisor. The following rules help mitigate issues.

Definitions for the rules below:

`core`:

  * `//pkg/sentry/...`
  * Transitive dependencies in `//pkg/...`

`runsc`:

  * `//runsc/...`

Rules:

  * No cgo in `core` or `runsc`. The final binary must be a statically-linked
    pure Go binary.

  * Any files importing "unsafe" must have a name ending in `_unsafe.go`.

  * `core` may only depend on the following packages:
    * Itself.
    * Go standard library.
      * Except (transitively) package "net" (this will result in a non-cgo
        binary). Use `//pkg/unet` instead.
    * `@com_golang_x_sys//unix:go_default_library` (Go import `golang.org/x/sys/unix`).
    * Generated Go protobuf packages.
    * `@com_github_golang_protobuf//proto:go_default_library` (Go import `github.com/golang/protobuf/proto`).
    * `@com_github_golang_protobuf//ptypes:go_default_library` (Go import `github.com/golang/protobuf/ptypes`).

  * `runsc` may only depend on the following packages:
    * All packages allowed for `core`.
    * `@com_github_google_subcommands//:go_default_library` (Go import `github.com/google/subcommands`).
    * `@com_github_opencontainers_runtime_spec//specs_go:go_default_library` (Go import `github.com/opencontainers/runtime-spec/specs_go`).

### Code reviews

All changes must be submitted via [Gerrit](https://gvisor-review.googlesource.com).

All submissions, including submissions by project members, require review.
Please see these [instructions](https://gvisor-review.googlesource.com/Documentation/).

### The small print

Contributions made by corporations are covered by a different agreement than
the one above, the
[Software Grant and Corporate Contributor License Agreement]
(https://cla.developers.google.com/about/google-corporate).

[gostyle][https://github.com/golang/go/wiki/CodeReviewComments]
