This package provides an emulation of Linux semantics for application virtual
memory mappings.

For completeness, this document also describes aspects of the memory management
subsystem defined outside this package.

# Background

We begin by describing semantics for virtual memory in Linux.

A virtual address space is defined as a collection of mappings from virtual
addresses to physical memory. However, userspace applications do not configure
mappings to physical memory directly. Instead, applications configure memory
mappings from virtual addresses to offsets into a file using the `mmap` system
call.[^mmap-anon] For example, a call to:

    mmap(
        /* addr = */ 0x400000,
        /* length = */ 0x1000,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        /* fd = */ 3,
        /* offset = */ 0);

creates a mapping of length 0x1000 bytes, starting at virtual address (VA)
0x400000, to offset 0 in the file represented by file descriptor (FD) 3. Within
the Linux kernel, virtual memory mappings are represented by *virtual memory
areas* (VMAs). Supposing that FD 3 represents file /tmp/foo, the state of the
virtual memory subsystem after the `mmap` call may be depicted as:

    VMA:     VA:0x400000 -> /tmp/foo:0x0

Establishing a virtual memory area does not necessarily establish a mapping to a
physical address, because Linux has not necessarily provisioned physical memory
to store the file's contents. Thus, if the application attempts to read the
contents of VA 0x400000, it may incur a *page fault*, a CPU exception that
forces the kernel to create such a mapping to service the read.

For a file, doing so consists of several logical phases:

1.  The kernel allocates physical memory to store the contents of the required
    part of the file, and copies file contents to the allocated memory.
    Supposing that the kernel chooses the physical memory at physical address
    (PA) 0x2fb000, the resulting state of the system is:

        VMA:     VA:0x400000 -> /tmp/foo:0x0
        Filemap:                /tmp/foo:0x0 -> PA:0x2fb000

    (In Linux the state of the mapping from file offset to physical memory is
    stored in `struct address_space`, but to avoid confusion with other notions
    of address space we will refer to this system as filemap, named after Linux
    kernel source file `mm/filemap.c`.)

2.  The kernel stores the effective mapping from virtual to physical address in
    a *page table entry* (PTE) in the application's *page tables*, which are
    used by the CPU's virtual memory hardware to perform address translation.
    The resulting state of the system is:

        VMA:     VA:0x400000 -> /tmp/foo:0x0
        Filemap:                /tmp/foo:0x0 -> PA:0x2fb000
        PTE:     VA:0x400000 -----------------> PA:0x2fb000

    The PTE is required for the application to actually use the contents of the
    mapped file as virtual memory. However, the PTE is derived from the VMA and
    filemap state, both of which are independently mutable, such that mutations
    to either will affect the PTE. For example:

    -   The application may remove the VMA using the `munmap` system call. This
        breaks the mapping from VA:0x400000 to /tmp/foo:0x0, and consequently
        the mapping from VA:0x400000 to PA:0x2fb000. However, it does not
        necessarily break the mapping from /tmp/foo:0x0 to PA:0x2fb000, so a
        future mapping of the same file offset may reuse this physical memory.

    -   The application may invalidate the file's contents by passing a length
        of 0 to the `ftruncate` system call. This breaks the mapping from
        /tmp/foo:0x0 to PA:0x2fb000, and consequently the mapping from
        VA:0x400000 to PA:0x2fb000. However, it does not break the mapping from
        VA:0x400000 to /tmp/foo:0x0, so future changes to the file's contents
        may again be made visible at VA:0x400000 after another page fault
        results in the allocation of a new physical address.

    Note that, in order to correctly break the mapping from VA:0x400000 to
    PA:0x2fb000 in the latter case, filemap must also store a *reverse mapping*
    from /tmp/foo:0x0 to VA:0x400000 so that it can locate and remove the PTE.

[^mmap-anon]: Memory mappings to non-files are discussed in later sections.

## Private Mappings

The preceding example considered VMAs created using the `MAP_SHARED` flag, which
means that PTEs derived from the mapping should always use physical memory that
represents the current state of the mapped file.[^mmap-dev-zero] Applications
can alternatively pass the `MAP_PRIVATE` flag to create a *private mapping*.
Private mappings are *copy-on-write*.

Suppose that the application instead created a private mapping in the previous
example. In Linux, the state of the system after a read page fault would be:

    VMA:     VA:0x400000 -> /tmp/foo:0x0 (private)
    Filemap:                /tmp/foo:0x0 -> PA:0x2fb000
    PTE:     VA:0x400000 -----------------> PA:0x2fb000 (read-only)

Now suppose the application attempts to write to VA:0x400000. For a shared
mapping, the write would be propagated to PA:0x2fb000, and the kernel would be
responsible for ensuring that the write is later propagated to the mapped file.
For a private mapping, the write incurs another page fault since the PTE is
marked read-only. In response, the kernel allocates physical memory to store the
mapping's *private copy* of the file's contents, copies file contents to the
allocated memory, and changes the PTE to map to the private copy. Supposing that
the kernel chooses the physical memory at physical address (PA) 0x5ea000, the
resulting state of the system is:

    VMA:     VA:0x400000 -> /tmp/foo:0x0 (private)
    Filemap:                /tmp/foo:0x0 -> PA:0x2fb000
    PTE:     VA:0x400000 -----------------> PA:0x5ea000

Note that the filemap mapping from /tmp/foo:0x0 to PA:0x2fb000 may still exist,
but is now irrelevant to this mapping.

[^mmap-dev-zero]: Modulo files with special mmap semantics such as `/dev/zero`.

## Anonymous Mappings

Instead of passing a file to the `mmap` system call, applications can instead
request an *anonymous* mapping by passing the `MAP_ANONYMOUS` flag.
Semantically, an anonymous mapping is essentially a mapping to an ephemeral file
initially filled with zero bytes. Practically speaking, this is how shared
anonymous mappings are implemented, but private anonymous mappings do not result
in the creation of an ephemeral file; since there would be no way to modify the
contents of the underlying file through a private mapping, all private anonymous
mappings use a single shared page filled with zero bytes until copy-on-write
occurs.

# Virtual Memory in the Sentry

The sentry implements application virtual memory atop a host kernel, introducing
an additional level of indirection to the above.

Consider the same scenario as in the previous section. Since the sentry handles
application system calls, the effect of an application `mmap` system call is to
create a VMA in the sentry (as opposed to the host kernel):

    Sentry VMA:     VA:0x400000 -> /tmp/foo:0x0

When the application first incurs a page fault on this address, the host kernel
delivers information about the page fault to the sentry in a platform-dependent
manner, and the sentry handles the fault:

1.  The sentry allocates memory to store the contents of the required part of
    the file, and copies file contents to the allocated memory. However, since
    the sentry is implemented atop a host kernel, it does not configure mappings
    to physical memory directly. Instead, mappable "memory" in the sentry is
    represented by a host file descriptor and offset, since (as noted in
    "Background") this is the memory mapping primitive provided by the host
    kernel. In general, memory is allocated from a temporary host file using the
    `pgalloc` package. Supposing that the sentry allocates offset 0x3000 from
    host file "memory-file", the resulting state is:

        Sentry VMA:     VA:0x400000 -> /tmp/foo:0x0
        Sentry filemap:                /tmp/foo:0x0 -> host:memory-file:0x3000

2.  The sentry stores the effective mapping from virtual address to host file in
    a host VMA by invoking the `mmap` system call:

        Sentry VMA:     VA:0x400000 -> /tmp/foo:0x0
        Sentry filemap:                /tmp/foo:0x0 -> host:memory-file:0x3000
          Host VMA:     VA:0x400000 -----------------> host:memory-file:0x3000

3.  The sentry returns control to the application, which immediately incurs the
    page fault again.[^mmap-populate] However, since a host VMA now exists for
    the faulting virtual address, the host kernel now handles the page fault as
    described in "Background":

        Sentry VMA:     VA:0x400000 -> /tmp/foo:0x0
        Sentry filemap:                /tmp/foo:0x0 -> host:memory-file:0x3000
          Host VMA:     VA:0x400000 -----------------> host:memory-file:0x3000
          Host filemap:                                host:memory-file:0x3000 -> PA:0x2fb000
          Host PTE:     VA:0x400000 --------------------------------------------> PA:0x2fb000

Thus, from an implementation standpoint, host VMAs serve the same purpose in the
sentry that PTEs do in Linux. As in Linux, sentry VMA and filemap state is
independently mutable, and the desired state of host VMAs is derived from that
state.

[^mmap-populate]: The sentry could force the host kernel to establish PTEs when
    it creates the host VMA by passing the `MAP_POPULATE` flag to
    the `mmap` system call, but usually does not. This is because,
    to reduce the number of page faults that require handling by
    the sentry and (correspondingly) the number of host `mmap`
    system calls, the sentry usually creates host VMAs that are
    much larger than the single faulting page.

## Private Mappings

The sentry implements private mappings consistently with Linux. Before
copy-on-write, the private mapping example given in the Background results in:

    Sentry VMA:     VA:0x400000 -> /tmp/foo:0x0 (private)
    Sentry filemap:                /tmp/foo:0x0 -> host:memory-file:0x3000
      Host VMA:     VA:0x400000 -----------------> host:memory-file:0x3000 (read-only)
      Host filemap:                                host:memory-file:0x3000 -> PA:0x2fb000
      Host PTE:     VA:0x400000 --------------------------------------------> PA:0x2fb000 (read-only)

When the application attempts to write to this address, the host kernel delivers
information about the resulting page fault to the sentry. Analogous to Linux,
the sentry allocates memory to store the mapping's private copy of the file's
contents, copies file contents to the allocated memory, and changes the host VMA
to map to the private copy. Supposing that the sentry chooses the offset 0x4000
in host file `memory-file` to store the private copy, the state of the system
after copy-on-write is:

    Sentry VMA:     VA:0x400000 -> /tmp/foo:0x0 (private)
    Sentry filemap:                /tmp/foo:0x0 -> host:memory-file:0x3000
      Host VMA:     VA:0x400000 -----------------> host:memory-file:0x4000
      Host filemap:                                host:memory-file:0x4000 -> PA:0x5ea000
      Host PTE:     VA:0x400000 --------------------------------------------> PA:0x5ea000

However, this highlights an important difference between Linux and the sentry.
In Linux, page tables are concrete (architecture-dependent) data structures
owned by the kernel. Conversely, the sentry has the ability to create and
destroy host VMAs using host system calls, but it does not have direct access to
their state. Thus, as written, if the application invokes the `munmap` system
call to remove the sentry VMA, it is non-trivial for the sentry to determine
that it should deallocate `host:memory-file:0x4000`. This implies that the
sentry must retain information about the host VMAs that it has created.

## Anonymous Mappings

The sentry implements anonymous mappings consistently with Linux, except that
there is no shared zero page.

# Implementation Constructs

In Linux:

-   A virtual address space is represented by `struct mm_struct`.

-   VMAs are represented by `struct vm_area_struct`, stored in `struct
    mm_struct::mmap`.

-   Mappings from file offsets to physical memory are stored in `struct
    address_space`.

-   Reverse mappings from file offsets to virtual mappings are stored in `struct
    address_space::i_mmap`.

-   Physical memory pages are represented by a pointer to `struct page` or an
    index called a *page frame number* (PFN), represented by `pfn_t`.

-   PTEs are represented by architecture-dependent type `pte_t`, stored in a
    table hierarchy rooted at `struct mm_struct::pgd`.

In the sentry:

-   A virtual address space is represented by type [`mm.MemoryManager`][mm].

-   Sentry VMAs are represented by type [`mm.vma`][mm], stored in
    `mm.MemoryManager.vmas`.

-   Mappings from sentry file offsets to host file offsets are abstracted
    through interface method [`memmap.Mappable.Translate`][memmap].

-   Reverse mappings from sentry file offsets to virtual mappings are abstracted
    through interface methods
    [`memmap.Mappable.AddMapping` and `memmap.Mappable.RemoveMapping`][memmap].

-   Host files that may be mapped into host VMAs are represented by type
    [`platform.File`][platform].

-   Host VMAs are represented in the sentry by type [`mm.pma`][mm] ("platform
    mapping area"), stored in `mm.MemoryManager.pmas`.

-   Creation and destruction of host VMAs is abstracted through interface
    methods
    [`platform.AddressSpace.MapFile` and `platform.AddressSpace.Unmap`][platform].

[memmap]: https://github.com/google/gvisor/blob/master/+/master/pkg/sentry/memmap/memmap.go
[mm]: https://github.com/google/gvisor/blob/master/+/master/pkg/sentry/mm/mm.go
[pgalloc]: https://github.com/google/gvisor/blob/master/+/master/pkg/sentry/pgalloc/pgalloc.go
[platform]: https://github.com/google/gvisor/blob/master/+/master/pkg/sentry/platform/platform.go
