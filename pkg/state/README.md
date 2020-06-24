# State Encoding and Decoding

The state package implements the encoding and decoding of data structures for
`go_stateify`. This package is designed for use cases other than the standard
encoding packages, e.g. `gob` and `json`. Principally:

*   This package operates on complex object graphs and accurately serializes and
    restores all relationships. That is, you can have things like: intrusive
    pointers, cycles, and pointer chains of arbitrary depths. These are not
    handled appropriately by existing encoders. This is not an implementation
    flaw: the formats themselves are not capable of representing these graphs,
    as they can only generate directed trees.

*   This package allows installing order-dependent load callbacks and then
    resolves that graph at load time, with cycle detection. Similarly, there is
    no analogous feature possible in the standard encoders.

*   This package handles the resolution of interfaces, based on a registered
    type name. For interface objects type information is saved in the serialized
    format. This is generally true for `gob` as well, but it works differently.

Here's an overview of how encoding and decoding works.

## Encoding

Encoding produces a `statefile`, which contains a list of chunks of the form
`(header, payload)`. The payload can either be some raw data, or a series of
encoded wire objects representing some object graph. All encoded objects are
defined in the `wire` subpackage.

Encoding of an object graph begins with `encodeState.Save`.

### 1. Memory Map & Encoding

To discover relationships between potentially interdependent data structures
(for example, a struct may contain pointers to members of other data
structures), the encoder first walks the object graph and constructs a memory
map of the objects in the input graph. As this walk progresses, objects are
queued in the `pending` list and items are placed on the `deferred` list as they
are discovered. No single object will be encoded multiple times, but the
discovered relationships between objects may change as more parts of the overall
object graph are discovered.

The encoder starts at the root object and recursively visits all reachable
objects, recording the address ranges containing the underlying data for each
object. This is stored as a segment set (`addrSet`), mapping address ranges to
the of the object occupying the range; see `encodeState.values`. Note that there
is special handling for zero-sized types and map objects during this process.

Additionally, the encoder assigns each object a unique identifier which is used
to indicate relationships between objects in the statefile; see `objectID` in
`encode.go`.

### 2. Type Serialization

The enoder will subsequently serialize all information about discovered types,
including field names. These are used during decoding to reconcile these types
with other internally registered types.

### 3. Object Serialization

With a full address map, and all objects correctly encoded, all object encodings
are serialized. The assigned `objectID`s aren't explicitly encoded in the
statefile. The order of object messages in the stream determine their IDs.

### Example

Given the following data structure definitions:

```go
type system struct {
    o *outer
    i *inner
}

type outer struct {
    a  int64
    cn *container
}

type container struct {
    n    uint64
    elem *inner
}

type inner struct {
    c    container
    x, y uint64
}
```

Initialized like this:

```go
o := outer{
    a: 10,
    cn: nil,
}
i := inner{
    x: 20,
    y: 30,
    c: container{},
}
s := system{
    o: &o,
    i: &i,
}

o.cn = &i.c
o.cn.elem = &i

```

Encoding will produce an object stream like this:

```
g0r1 = struct{
     i: g0r3,
     o: g0r2,
}
g0r2 = struct{
     a: 10,
     cn: g0r3.c,
}
g0r3 = struct{
     c: struct{
             elem: g0r3,
             n: 0u,
     },
     x: 20u,
     y: 30u,
}
```

Note how `g0r3.c` is correctly encoded as the underlying `container` object for
`inner.c`, and how the pointer from `outer.cn` points to it, despite `system.i`
being discovered after the pointer to it in `system.o.cn`. Also note that
decoding isn't strictly reliant on the order of encoded object stream, as long
as the relationship between objects are correctly encoded.

## Decoding

Decoding reads the statefile and reconstructs the object graph. Decoding begins
in `decodeState.Load`. Decoding is performed in a single pass over the object
stream in the statefile, and a subsequent pass over all deserialized objects is
done to fire off all loading callbacks in the correctly defined order. Note that
introducing cycles is possible here, but these are detected and an error will be
returned.

Decoding is relatively straight forward. For most primitive values, the decoder
constructs an appropriate object and fills it with the values encoded in the
statefile. Pointers need special handling, as they must point to a value
allocated elsewhere. When values are constructed, the decoder indexes them by
their `objectID`s in `decodeState.objectsByID`. The target of pointers are
resolved by searching for the target in this index by their `objectID`; see
`decodeState.register`. For pointers to values inside another value (fields in a
pointer, elements of an array), the decoder uses the accessor path to walk to
the appropriate location; see `walkChild`.
