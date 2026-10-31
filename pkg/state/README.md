# State Encoding and Decoding

The state package implements the encoding and decoding of data structures for
`go_stateify`. This package is designed for use cases other than the standard
encoding packages, e.g. `gob` and `json`. Principally:

*   This package operates on complex object graphs and accurately serializes and
    restores all relationships. That is, you can have things like: intrusive
    pointers, cycles, pointers into the middle of objects, slices sharing
    backing arrays, and pointer chains of arbitrary depths.

*   This package allows installing order-dependent load callbacks and then
    resolves that graph at load time, with cycle detection.

*   This package handles the resolution of interfaces, based on a registered
    type name.

*   Streams can only be loaded by the binary that saved them (more precisely, by
    a binary with the same registered types; this is checked with a schema
    fingerprint). This allows a compact format without field names or type tags,
    decoded without reflection.

## Engines

The package provides two serialization engines:

*   The **graph engine** (enabled by default, or via `EnableGraphEngine(true)` /
    `--state-engine=graph`), documented below, which encodes and decodes object
    graphs without runtime reflection.
*   The legacy **wire engine** (`EnableGraphEngine(false)` /
    `--state-engine=wire`), which encodes tagged `pkg/state/wire` objects via
    `reflect`.

`Load` and `pkg/state/pretty` inspect the stream header and automatically decode
either format.

## Types

Each Go type is described by a `typeInfo`, built once on first use and cached.
Values are saved and loaded by switching on their kind and using `unsafe`
pointers. Generated `StateSave` and `StateLoad` methods call typed `Sink` and
`Source` methods (`SaveInt64`, `LoadInt64`, etc.) for predeclared scalar,
string, and byte-slice fields, `LoadValueTo` and `AfterLoadTo` to avoid closure
allocations, and `Save`/`Load` (passing field pointers as `any`, whose interface
type word identifies the cached `typeInfo`) for other fields. Pure scalar
structs and `identtype` wrappers without hooks are registered via
`RegisterNoHooks` / `RegisterIdent` and copied directly as raw bytes.

`StateSave` must save fields in the same order as `StateLoad` loads them.

## Encoding

Encoding begins with `graphEncodeState.save`.

The graph is divided into *objects*: regions of memory saved as a unit, which
pointers may point into. An object is either a single value (the target of a
pointer), an array (the backing array of slices), or a map. Pointers are saved
as indices of *targets*: a location (object and byte offset) within an object.

Objects are encoded as they are found, starting from the root, in a breadth
first order. When a pointer is saved, its target is looked up by address. If it
is not known, the object index (which maps blocks of memory to the objects
intersecting them) is searched for an object containing it. If there is none, a
new object is created, which absorbs any objects that it contains: their targets
are relocated into the new object, and their encodings (if done) are reused when
the new object is encoded, so that `StateSave` is called once per value.

Of arrays, only the elements within slices, or pointed to, are saved.

The stream is:

1.  A magic number and the schema fingerprint.
2.  The type table: the types of objects, and of values held in interfaces.
3.  The object table: the kind and type of each object.
4.  The target table: the object and offset of each target.
5.  The data of each object, in order.

## Decoding

Decoding begins with `graphDecodeState.load`. It allocates all objects (except
maps, which are allocated when they are first referred to, since their exact
type is only known then), resolves all targets to pointers, and then decodes the
data of each object in a single pass. Then, the load callbacks of objects are
run once the objects they wait for are complete. Cycles of waiting objects are
detected and reported as errors.
