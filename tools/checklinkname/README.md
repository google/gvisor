# `checklinkname` Analyzer

`checklinkname` is an analyzer to provide rudimentary type-checking for
`//go:linkname` directives. Since `//go:linkname` only affects linker behavior,
there is no built-in type safety and it is the programmer's responsibility to
ensure the types on either side are compatible.

`checklinkname` helps with this by checking that uses match expectations, as
defined in this package.

`known.go` contains the set of known linkname targets. For most functions, we
expect identical types on both sides of the linkname. In a few cases, the types
may be slightly different (e.g., local redefinition of internal type). It is
still the responsibility of the programmer to ensure the signatures in
`known.go` are compatible and safe.

## Findings

Here are the most common findings from this package, and how to resolve them.

### `runtime.foo signature got "BAR" want "BAZ"; stdlib type changed?`

The definition of `runtime.foo` in the standard library does not match the
expected type in `known.go`. This means that the function signature in the
standard library changed.

Addressing this will require creating a new linkname directive in a new Go
version build-tagged in any packages using this symbol. Be sure to also check to
ensure use with the new version is safe, as function constraints may have
changed in addition to the signature.

<!-- TODO(b/165820485): This isn't yet explicitly supported. -->

`known.go` will also need to be updated to accept the new signature for the new
version of Go.

### `Cannot find known symbol "runtime.foo"`

The standard library has removed runtime.foo entirely. Handling is similar to
above, except existing code must transition away from the symbol entirely (note
that is may simply be renamed).

### `linkname to unknown symbol "mypkg.foo"; add this symbol to checklinkname.knownLinknames type-check against the remote type`

A package has added a new linkname directive for a symbol not listed in
`known.go`. Address this by adding a new entry for the target symbol. The
`local` field should be the expected type in your package, while `remote` should
be expected type in the remote package (e.g., in the standard library). These
are typically identical, in which case `remote` can be omitted.

### `usage: //go:linkname localname [linkname]`

Malformed `//go:linkname` directive. This should be accompanied by a build
failure in the package.
