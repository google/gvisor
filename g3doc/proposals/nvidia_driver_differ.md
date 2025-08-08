# Nvidia Driver Differ Tool

Status as of 2024-08-14: Completed. To get an overview of what was ultimately
implemented, check out the
[presentation here](https://github.com/google/gvisor/blob/master/g3doc/presentations/nvidia_tooling.pdf).

## Overview

This tool is intended to make it easier to support new Nvidia driver versions
within nvproxy. Any new version of an Nvidia driver can come with changes to its
ioctl structs, and if nvproxy supports those structs, it will have to copy those
changes as well. Prior to the implementation of this proposal, however, finding
those changes is both difficult and tedious. This tool attempts to automate the
bulk of this work.

This document goes over some design proposals of how this tool should be built,
especially how it should interface with nvproxy.

## Problem Statement

Let's say we want to add support for a new driver version B. At a high level,
the work of this tool can be broken into the following steps:

1.  Find the nearest ancestor version, A, that nvproxy supports. nvproxy
    supports multiple major version numbers, so these versions form a tree
    instead of a simple line of dependencies.
2.  Get the list of currently used structs in nvproxy for version A.
3.  For each struct, compare its definition in versions A and B. Report any
    differences–type, number, and ordering of fields all matter.

The biggest roadblock to implementing this is that the only immediate
information reported by nvproxy is the ioctl calls it supports. Some ioctl calls
have corresponding structs defined, but:

-   There is no way to directly get this mapping; it would require analysis of
    the nvproxy code with some AST parser.
-   Some ioctls have multiple structs defined due to changes across version; we
    need some way to know which struct nvproxy is using for version A.
-   Some ioctls simply don't have struct definitions written out, since they're
    simply passed by copying a given `size` bytes. Most control commands are
    like this.

Additionally, nested structs are also a concern. For example, some structs may
be defined like so:

```go
type IOCTL_FOO struct {
    Foo    uint32
    Bars   [MAX_BARS]IOCTL_BAR
}

type IOCTL_BAR struct {
    Bar   uint32
}
```

This means we not only have to map ioctl calls to their corresponding structs,
but also (recursively) parse their fields to see if there are nested structs.

## Proposal

We can split this tool into two parts. The first part can be a Go tool that is
built against nvproxy and finds the list of structs for version B. Once we have
a specific list of structs to look up, we can pass that to a C++ tool that uses
[Clang's C++ AST Matcher API](https://clang.llvm.org/docs/LibASTMatchersReference.html)
to find the corresponding struct definitions in the driver source code. These
definitions are then passed back to the Go tool, which does the necessary
diffing and reporting back to the user.

### Fetching struct names from nvproxy

The primary problem to tackle on the Go side is how to get the list of struct
names nvproxy depends on for a given version B. Since this system should allow
for versioning of these struct names, we can extend the existing `driverABI`
struct to include this information.

However, almost every normal use case of `driverABI` will not need to use these
names, and they should not be sitting around wasting memory. Thus, we can add a
`getStructNames` function to `driverABI` that will construct and return the list
of relevant names only when they are needed. It should look like this:

```go
type driverABI struct {
    frontendIoctl   map[uint32]frontendIoctlHandler
    uvmIoctl        map[uint32]uvmIoctlHandler
    controlCmd      map[uint32]controlCmdHandler
    allocationClass map[nvgpu.ClassID]allocationClassHandler

    getStructNames driverStructNamesFunc
}

type driverStructNamesFunc func() *driverStructNames

type driverStructNames struct {
    frontendNames   map[uint32][]string
    uvmNames        map[uint32][]string
    controlNames    map[uint32][]string
    allocationNames map[nvgpu.ClassID][]string
}
```

The fields in `driverStructNames` map every ioctl to a list of struct names that
it depends on (this is a list to support the case of nested structs). By
explicitly mapping each struct name to their corresponding ioctl, it should make
this list easy to maintain. We can compare against the ioctls included in the
ABI map to ensure every ioctl call is accounted for in each version. It also
makes it easier to modify definitions for a specific ioctl number due to a
version change.

There are a few cases to consider when generating the list of names for an
ioctl:

-   For ioctls with a struct defined in nvproxy, we can provide a function
    `getStructName(any)` that takes a struct and returns its corresponding
    driver name in a `[]string`. How this should be done is discussed further
    below.
-   For ioctls without a struct defined in nvproxy, we can directly write the
    corresponding struct names. This can be done with a function
    `simpleIoctl(name)` that simply returns a `[]string` with one element, to
    make it more explicit.
-   Finally, there are some ioctls (or maybe just `NV_ESC_RM_ALLOC`) that allow
    multiple types of parameters. In this case, corresponding lists for each
    parameter type can be merged.

Concretely, this would look something like this:

```go
driverStructNames{
    frontendNames: map[uint32][]string{
        NV_ESC_RM_ALLOC_MEMORY: append(getStructName(NVOS21Parameters{}), getStructName(NVOS64Parameters{})...),
    },
    uvmNames: map[uint32][]string{
        UVM_ALLOC_SEMAPHORE_POOL: getStructName(UVM_ALLOC_SEMAPHORE_POOL_PARAMS{})
    },
    controlCmd: map[uint32][]string{
        NV2080_CTRL_CMD_GPU_GET_NAME_STRING: simpleIoctl("NV2080_CTRL_GPU_GET_NAME_STRING_PARAMS"),
    },
    allocationNames: map[nvgpu.ClassID][]string{
        NV01_MEMORY_SYSTEM: getStructName(NV_MEMORY_ALLOCATION_PARAMS{}),
    },
}
```

Looking specifically now at `getStructName`, there are a few ways in which it
can be implemented:

1.  We can require that struct names in nvproxy are exactly the same as their
    counterpart in the Nvidia driver. This way, Go's
    [reflect](https://pkg.go.dev/reflect) package can be used to simply read the
    name of the struct being passed in.

    To handle versioning changes, we can agree on some suffix format. For
    example, everything after a double underscore is ignored. This way, both
    `PARAMS` and `PARAMS__V550` can be defined.

2.  We can introduce struct tags that specify the name of the corresponding
    struct in the Nvidia driver code, which would always sit on the first field.
    This could look something like this:

    ```go
    type IOCTL_FOO_V550 struct {
      Foo    uint32   `nvproxy:"ioctl_foo"`
      Bars   [MAX_BARS]IOCTL_BAR
      Baz    uint64
    }
    ```

    This struct tag can be read using reflect. For structs that are named the
    same between nvproxy and the Nvidia driver, we can also have a convenient
    `nvproxy:"same"` case that simply uses the struct’s name.

3.  Instead of using a struct tag, we can use a struct comment similar to `//
    +marshal` or `// +stateify`. An external tool would then run on the nvproxy
    package, find each struct with the struct comment, and implement an
    interface that reports back the corresponding driver name.

    ```go
    type NvidiaDriverStruct interface {
      func GetDriverName() string
    }

    // +nvproxy ioctl_foo
    type IOCTL_FOO_V550 struct {
      Foo    uint32
      Bars   [MAX_BARS]IOCTL_BAR
      Baz    uint64
    }

    // Auto-generated
    func (s IOCTL_FOO_V550) GetDriverName() string {
      return "ioctl_foo"
    }
    ```

    The use of an external tool makes this method a lot more involved, and
    potentially expensive to maintain. The main benefit is that it is a better
    convention than requiring tags on the first field. The code will also be
    similar to `go_marshal` or `go_stateify`, so a lot could be copied over.
    Specifically, the code generation step and the code to collect all annotated
    types in `Generator.collectMarshallableTypes` can be the same.

Comparing these three ideas, numbers 1 and 2 are definitely the easiest to
implement. Idea 2 will be more robust as well, since we don’t have to worry
about Nvidia driver structs potentially having double underscores or whatever
separator we decide on. In the end, idea 2 was implemented; if it is important
to maintaining convention, idea 3 can still be implemented afterwards.

There is also the problem of nested structs that needs to be addressed. Although
the Go side can try and tackle this problem, it would be hard to maintain for
the simple structs that are not defined in nvproxy, as we would have to manually
check if they have nested structs and write down what they are. Thus, it would
be easier to make the C++ Clang tool do this, and simply have the Go tool find
the list of all top-level structs.

### C++ Clang parser

After gathering a list of struct names to verify, this tool can locally clone
the code for both versions A and B. From here, Clang's C++ AST Matcher API can
be used to generate an AST and find the struct definitions given the name.

The Clang API includes the ability to quickly set up command line tools to run
the AST matcher; this
[tutorial](https://clang.llvm.org/docs/LibASTMatchersTutorial.html) in the
documentation covers everything this tool needs to do. Out of the box, it takes
in a source file, and allows you to run any set of matchers on that source file.
This means we can create a small C++ file that `#include`s all the header files
that contain struct definitions, similar to what
[Geohot does with his sniffer](https://github.com/geohot/cuda_ioctl_sniffer/blob/master/pstruct/include.cc).
Clang will automatically expand these `#include`s, so any struct defined in
there will be matchable.

In the driver source code, all structs are named via a `typedef`. This means the
tool should try and match against a `typedef` with a given struct name, and then
look at the struct type aliases. This is done with the following Clang matcher
expression:

```c++
typedefDecl(
  allOf(
    hasName(struct_name),
    // Match and bind to the struct declaration.
    hasType(
      // Need to specify elaboratedType, otherwise hasType
      // will complain that the type is ambiguous.
      elaboratedType(
        hasDeclaration(recordDecl().bind("struct_decl"))
      )
    )
  )
).bind("typedef_decl");
```

A few structs in the driver share the same definition, so they are defined via
`typedef`s to each other. These structs will not get matched by the expression
above; instead, the tool should check that the typedefDecl is mapped to another
`typedefDecl` rather than a `recordDecl`, like so:

```c++
// Matches definitions like
// typedef NV906F_CTRL_GET_CLASS_ENGINEID_PARAMS NVC36F_CTRL_GET_CLASS_ENGINEID_PARAMS;
typedefDecl(
  allOf(
    hasName(struct_name),
    // Match and bind to the struct declaration.
    hasType(
      // Need to specify elaboratedType, otherwise hasType
      // will complain that the type is ambiguous.
      elaboratedType(
        hasDeclaration(typedefDecl())
      )
    )
  )
).bind("typedef_decl");
```

These cases can be recorded as type aliases in the JSON output, described in
more detail below.

Running this matcher will provide a binding to a `clang::RecordDecl` node
corresponding to the struct definition. From here, we can iterate through the
fields and get their name and type using `clang::FieldDecl.getNameAsString()`
and `clang::FieldDecl->getType().getAsString()`.

One edge case is if the field type is an anonymous struct or union, like so:

```c++
typedef struct IOCTL_WITH_UNION {
  int foo;
  union {
    int bar;
    int baz;
  } data;
}
```

Trying to get the type name directly will yield an auto generated name that
includes the absolute file path, which is not easy to compare. Instead, the tool
should check if a type is anonymous using `clang::Type.hasUnnamedOrLocalType`,
and create a standardized name if not. The standardized name can be of the form
`PARENT_RECORD::FIELD_t`; for example, `IOCTL_WITH_UNION::data_t` for the
example above.

The Clang tool should also recurse into any nested structs. Since it already has
the `clang::QualType` of each field, there are two possible cases to consider:

-   If the type is an array, it should recurse on the array element type.
-   If the type is a struct, it can recurse on the type's `clang::RecordDecl`
    node.

Along the way, the tool can also record the true type of any other field types
it find using `clang::QualType.getCanonicalType()`, in case these simple types
ever change. For example, the tool might record that `NvHandle` is an `unsigned
int`

Finally, the Go side needs some way to interface with the C++ Clang side. To
make things simple, the inputs and outputs can be encoded in JSON. Overall,
interfacing with the parser would go something like this:

```bash
./driver_ast_parser --input=input.json source_file.cc
```

Input:

```json
{
    "structs": ["STRUCT", "NAMES", "HERE", ...],
    "constants": ["CONSTANT", "NAMES", "HERE", ...]
}
```

Output:

```json
{
    // Named records since this captures both structs and unions found
    "records": {
        "STRUCT_NAME": {
            "fields": [
                {"name": "field1", "type": "int"},
                {"name": "field2", "type": "NvHandle"}
            ],
            "source": "/path/to/source/file.cc:line_number"
        },
        ...
    },
    // All the typedefs found
    "aliases": {
        "NvHandle": "unsigned int"
    },
    "constants": {
      "CONSTANT_NAME": UINT_VALUE
    }
}
```

### Remaining details

Beyond the nvproxy changes and C++ Clang parser, there are a few other details
to work out.

The first is actually getting the driver source code locally for Clang to parse
through. This can be done by cloning from the NVIDIA driver's GitHub repo:

```bash
git clone -b $VERSION --depth 1 https://github.com/NVIDIA/open-gpu-kernel-modules.git $SAVE_PATH
```

Next, the parser needs some source file to analyze and parse through. As
mentioned above, the easiest way to make this would be to create a single C++
file that `#include`s every relevant driver header file with struct definitions.
Finding these relevant header files does require hard-coding some paths;
however, the driver file structure seems very stable for now. Currently, the
list of header files is:

-   Frontend:
    -   `src/common/sdk/nvidia/inc/nvos.h`
    -   `src/nvidia/arch/nvalloc/unix/include/nv-ioctl.h`
    -   `src/nvidia/arch/nvalloc/unix/include/nv-unix-nvos-params-wrappers.h`
-   UVM:
    -   `kernel-open/nvidia-uvm/uvm_ioctl.h`
    -   `kernel-open/nvidia-uvm/uvm_linux_ioctl.h`
-   Control commands:
    -   `src/common/sdk/nvidia/inc/ctrl/*.h`
    -   `src/common/sdk/nvidia/inc/ctrl/*/*.h`
-   Allocation classes:
    -   `src/common/sdk/nvidia/inc/class/*.h`

These header files also `#include` from other header files. The include paths
for these files are as follows:

-   Non-UVM:
    -   `src/common/sdk/nvidia/inc`
    -   `src/common/shared/inc`
    -   `src/nvidia/arch/nvalloc/unix/include`
-   UVM:
    -   `kernel-open/common/inc`

Unfortunately, there are many duplicate definitions between non-UVM and UVM
files. This means that the C++ parser should be run **twice** per driver
version, for the non-UVM and UVM sources respectively.

To let Clang know about these include paths, a `compile_commands.json` file is
needed. The format of this file is documented
[here](https://clang.llvm.org/docs/JSONCompilationDatabase.html), but for the
use case of this tool, the structure will always look as follows:

```json
[
    { "directory": "source/file/directory",
      "arguments": ["clang", "-I", "include/path/1", "-I", "include/path/2", ..., "non_uvm_source_file.cc"],
      "file": "non_uvm_source_file.cc"
    },
    // repeated for UVM source file
]
```

Clang **requires** that the file is called `compile_commands.json`, and it
assumes that it exists in the same directory as the file being parsed. As such,
the differ will likely need to create a temporary directory when running, with
the following format:

```
temp_dir
  \ driver_source_dir
  \ compile_commands.json
  \ non_uvm_source_file.cc
  \ uvm_source_file.cc
```

Altogether, the differ will behave as follows:

1.  Get the versions A and B to be diffed.
    -   Initially, these can just be passed in via command line arguments. In
        the future, the tool can just take in the new version B, and
        automatically figure out the latest version A that nvproxy supports.
2.  Query nvproxy for the list of structs it depends on for version A.
3.  Save the list of structs to a temporary JSON file.
4.  For each version:
    1.  Create a temporary directory.
    2.  Clone the git repo for the current version.
    3.  Match the list of header file paths to create `non_uvm_source_file.cc`
        and `uvm_source_file.cc`.
    4.  Create `compile_commands.json`.
    5.  Run the C++ parser on both source files, referring to the list of
        structs saved above.
    6.  Combine outputs from two parser runs.
5.  Compare the combined outputs of each version, reporting any differences
    found.

### Tests

Do you love tests? Well luckily for you, there are a few tests that should be
built around this diffing tool.

First, a few continuous tests should be made to ensure the list of struct names
is kept up to date. For every version covered by nvproxy’s ABI tree, one test
can check whether there are any supported ioctls that are missing in
`driverStructNames`, and another can run the parser to verify that every struct
name reported in `driverStructNames` actually exists in the driver source code.

There should also be a continuous test that uses this tool to verify that
nvproxy is correct. Rather than trying to use the differ, however, it might be
easier to just use the C++ Clang parser and verify individual versions of the
ABI. This test should take the `driverStructNames` for a given version, find the
corresponding driver struct definitions, and then match it against the nvproxy
equivalent struct.

This would require augmenting the `driverABI` mapping to also return struct
instances, which can be read using Go’s `reflect` library. Specifically, instead
of mapping ioctls to `[]strings`, they can be mapped to slices of strings and
struct instances, like so:

```go
type DriverStruct struct {
    Name          string
    Instance    any
}

type driverStructNames struct {
    frontendNames   map[uint32][]DriverStruct
    uvmNames        map[uint32][]DriverStruct
    controlNames    map[uint32][]DriverStruct
    allocationNames map[nvgpu.ClassID][]DriverStruct
}
```

This allows for comparisons of struct definitions within nvproxy and the NVIDIA
driver.

When verifying a struct, there are a few cases that can happen. The first case
is when nvproxy treats an ioctl as simple (`DriverStruct.Instance == nil`). The
test should look for a few signs in the driver definition, to verify that the
struct is actually simple:

-   If a field is `NvP64`, the struct is not simple.
-   If a field name ends in `"fd"`, the struct is not simple.

Another case is when nvproxy defines a struct for a parameter, but the Nvidia
driver uses a simple type alias. `NvHandle` seems to be the only example of
this:

```go
// nvproxy definition
type Handle struct {
    Val uint32 `nvproxy:"NvHandle"`
}
```

```c++
// Driver definition
typedef NvU32 NvHandle;
```

To verify this, the test can compare the sizes of the two types and ensure they
remain identical.

The last case is when both nvproxy and the driver have struct definitions. When
thinking about how this can be done, there are a few complications to keep in
mind:

-   Sometimes nvproxy flattens structs or unions. For example:

    ```go
    // nvproxy definition
    type IOCTL_WITH_NESTED_STRUCT struct {
      int foo;
      int bar;
      int baz;
    }
    ```

    ```c++
    // Driver definition
    typedef struct {
        int foo;

        struct {
          int bar;
          int baz;
        } data;
    } IOCTL_WITH_NESTED_STRUCT;
    ```

-   Some unions are simply represented by `[n]byte` fields.

-   Some nvproxy structs use struct embedding, which should be accounted for
    when looking through the fields using `reflect`.

    ```go
    type NV_MEMORY_ALLOCATION_PARAMS_V545 struct {
      NV_MEMORY_ALLOCATION_PARAMS `nvproxy:"NV_MEMORY_ALLOCATION_PARAMS"`
      NumaNode                    int32
      _                           uint32
    }
    ```

-   nvproxy structs can have additional fields added for padding.

To alleviate the problem of nested or flattened structs, all struct definitions
can be pre-flatten before comparing them. This will yield an array of fields for
both sides. For example, this definition

```c++
typedef struct {
    int a1;
    int a2;
    IOCTL_B b;
} IOCTL_A;

typedef struct {
    bool b1;
    bool b2;
    IOCLT_C c;
    bool b3;
} IOTCL_B;

typedef struct {
    unsigned int c;
} IOCTL_C;
```

would be flattened into

```c++
[
  int a1,
  int a2,
  bool b1,
  bool b2,
  unsigned int c,
  bool b3,
]
```

Next, fields that **have the same offset** should be compared. Due to padding
and union types, multiple nvproxy fields may correspond to a single driver
field; however, as long as each driver field has a corresponding nvproxy field
at the same offset, the extraneous fields do not matter. The following
pseudo-code accomplishes all of this:

```
doStructsMatch(nvproxyType, driverType) -> bool
  if nvproxyType.Size != driverType.Size:
    return false

  nvproxyFields = Flatten(nvproxyType)
  driverFields = Flatten(driverType)

  for each ith field in driverFields:
    find the jth field in nvproxyFields with the same offset
    if such a field doesn't exist:
      return false

    if !doTypesMatch(nvproxyFields[j].Type, driverFields[i].Type):
      return false
  return true

doTypesMatch(nvproxyType, driverType) -> bool
  if driverType is an array:
    if nvproxyType is not an array of the same length:
      return false
    recurse on the base type of each array

  // These are special types that nvproxy has type definitions for
  Check the following mappings from driverType -> nvproxyType:
    NvHandle -> Handle
    NvP64 -> P64
    NvProcessorUuid -> NvUUID

  // E.g. NvU32 aliases unsigned int
  if driverType has an alias:
    driverType = alias
  Check the following mappings from driverType -> nvproxyType:
    char -> byte
    unsigned char -> uint8
    short -> int16
    unsigned short -> uint16
    int -> int32
    unsigned int -> uint32
    long long -> int64
    unsigned long long -> uint64
    enum _ -> uint32
    union -> [n]byte
    struct -> doStructsMatch(nvproxyType, driverType)
```

This all requires some changes on the C++ parser side as well. Namely, it should
report sizes for `records` and `aliases`, whether a record is a union type, and
offsets for each record field. This can be done with
`clang::ASTContext.getTypeInfo`, `clang::TagDecl.isUnion`, and
`clang::ASTContext.getFieldOffset` respectively.

## Future Work

### Interpreting struct field names

Occasionally, driver structs might change not by introducing a new field, but by
changing the purpose of an existing field. For example, a previously reserved
integer field might now be used as a file descriptor field, meaning that nvproxy
would need to add special handling for it. Although the differ reports changes
in field names, it could also report any code changes it thinks are necessary.
This could behave similarly to the verification test, which looks at simple
clues such as `NvP64` types or fields ending in `"fd"`.

### Check ABI ranges for nvproxy

Currently, nvproxy only support specific versions of the Nvidia driver. However,
many intermediate versions likely do not have any breaking changes, and it is
detrimental to users if they are forced to only use some specific driver
versions. This differ tool could be used to find ranges of ABI versions that
have no change, and nvproxy could support any version with this range.

### Additional nvproxy struct tags

In the future, nvproxy can record additional information using the
`nvproxy:"..."` tags. For example, any `NvP64` field could be tagged with the
struct type that the pointer represents, allowing tests to recurse on these
hidden dependencies.
