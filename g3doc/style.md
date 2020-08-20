# Provisional style guide

> These guidelines are new and may change. This note will be removed when
> consensus is reached.

Not all existing code will comply with this style guide, but new code should.
Further, it is a goal to eventually update all existing code to be in
compliance.

## All code

### Early exit

All code, unless it substantially increases the line count or complexity, should
use early exits from loops and functions where possible.

## Go specific

All Go code should comply with the [Go Code Review Comments][gostyle] and
[Effective Go][effective_go] guides, as well as the additional guidelines
described below.

### Mutexes

#### Naming

Mutexes should be named mu or xxxMu. Mutexes as a general rule should not be
exported. Instead, export methods which use the mutexes to avoid leaky
abstractions.

#### Location

Mutexes should be sibling fields to the fields that they protect. Mutexes should
not be declared as global variables, instead use a struct (anonymous ok, but
naming conventions still apply).

Mutexes should be ordered before the fields that they protect.

#### Comments

Mutexes should have a comment on their declaration explaining any ordering
requirements (or pointing to where this information can be found), if
applicable. There is no need for a comment explaining which fields are
protected.

Each field or variable protected by a mutex should state as such in a comment on
the field or variable declaration.

### Function comments

Functions with special entry conditions (e.g., a lock must be held) should state
these conditions in a `Preconditions:` comment block. One condition per line;
multiple conditions are specified with a bullet (`*`).

Functions with notable exit conditions (e.g., a `Done` function must eventually
be called by the caller) can similarly have a `Postconditions:` block.

### Unused returns

Unused returns should be explicitly ignored with underscores. If there is a
function which is commonly used without using its return(s), a wrapper function
should be declared which explicitly ignores the returns. That said, in many
cases, it may make sense for the wrapper to check the returns.

### Formatting verbs

Built-in types should use their associated verbs (e.g. %d for integral types),
but other types should use a %v variant, even if they implement fmt.Stringer.
The built-in `error` type should use %w when formatted with `fmt.Errorf`, but
only then.

### Wrapping

Comments should be wrapped at 80 columns with a 2 space tab size.

Code does not need to be wrapped, but if wrapping would make it more readable,
it should be wrapped with each subcomponent of the thing being wrapped on its
own line. For example, if a struct is split between lines, each field should be
on its own line.

#### Example

```go
_ = exec.Cmd{
  Path: "/foo/bar",
  Args: []string{"-baz"},
}
```

## C++ specific

C++ code should conform to the [Google C++ Style Guide][cppstyle] and the
guidelines described for tests.

[cppstyle]: https://google.github.io/styleguide/cppguide.html
[gostyle]: https://github.com/golang/go/wiki/CodeReviewComments
[effective_go]: https://golang.org/doc/effective_go.html
