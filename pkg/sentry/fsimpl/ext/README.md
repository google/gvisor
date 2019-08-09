## EXT(2/3/4) File System

This is a filesystem driver which supports ext2, ext3 and ext4 filesystems.
Linux has specialized drivers for each variant but none which supports all. This
library takes advantage of ext's backward compatibility and understands the
internal organization of on-disk structures to support all variants.

This driver implementation diverges from the Linux implementations in being more
forgiving about versioning. For instance, if a filesystem contains both extent
based inodes and classical block map based inodes, this driver will not complain
and interpret them both correctly. While in Linux this would be an issue. This
blurs the line between the three ext fs variants.

Ext2 is considered deprecated as of Red Hat Enterprise Linux 7, and ext3 has
been superseded by ext4 by large performance gains. Thus it is recommended to
upgrade older filesystem images to ext4 using e2fsprogs for better performance.

### Read Only

This driver currently only allows read only operations. A lot of the design
decisions are based on this feature. There are plans to implement write (the
process for which is documented in the future work section).

### Performance

One of the biggest wins about this driver is that it directly talks to the
underlying block device (or whatever persistent storage is being used), instead
of making expensive RPCs to a gofer.

Another advantage is that ext fs supports fast concurrent reads. Currently the
device is represented using a `io.ReaderAt` which allows for concurrent reads.
All reads are directly passed to the device driver which intelligently serves
the read requests in the optimal order. There is no congestion due to locking
while reading in the filesystem level.

Reads are optimized further in the way file data is transferred over to user
memory. Ext fs directly copies over file data from disk into user memory with no
additional allocations on the way. We can only get faster by preloading file
data into memory (see future work section).

The internal structures used to represent files, inodes and file descriptors use
a lot of inheritance. With the level of indirection that an interface adds with
an internal pointer, it can quickly fragment a structure across memory. As this
runs along side a full blown kernel (which is memory intensive), having a
fragmented struct might hurt performance. Hence these internal structures,
though interfaced, are tightly packed in memory using the same inheritance
pattern that pkg/sentry/vfs uses. The pkg/sentry/fsimpl/ext/disklayout package
makes an execption to this pattern for reasons documented in the package.

### Security

This driver also intends to help sandbox the container better by reducing the
surface of the host kernel that the application touches. It prevents the
application from exploiting vulnerabilities in the host filesystem driver. All
`io.ReaderAt.ReadAt()` calls are translated to `pread(2)` which are directly
passed to the device driver in the kernel. Hence this reduces the surface for
attack.

The application can not affect any host filesystems other than the one passed
via block device by the user.

### Future Work

#### Write

To support write operations we would need to modify the block device underneath.
Currently, the driver does not modify the device at all, not even for updating
the access times for reads. Modifying the filesystem incorrectly can corrupt it
and render it unreadable for other correct ext(x) drivers. Hence caution must be
maintained while modifying metadata structures.

Ext4 specifically is built for performance and has added a lot of complexity as
to how metadata structures are modified. For instance, files that are organized
via an extent tree which must be balanced and file data blocks must be placed in
the same extent as much as possible to increase locality. Such properties must
be maintained while modifying the tree.

Ext filesystems boast a lot about locality, which plays a big role in them being
performant. The block allocation algorithm in Linux does a good job in keeping
related data together. This behavior must be maintained as much as possible,
else we might end up degrading the filesystem performance over time.

Ext4 also supports a wide variety of features which are specialized for varying
use cases. Implementing all of them can get difficult very quickly.

Ext(x) checksums all its metadata structures to check for corruption, so
modification of any metadata struct must correspond with re-checksumming the
struct. Linux filesystem drivers also order on-disk updates intelligently to not
corrupt the filesystem and also remain performant. The in-memory metadata
structures must be kept in sync with what is on disk.

There is also replication of some important structures across the filesystem.
All replicas must be updated when their original copy is updated. There is also
provisioning for snapshotting which must be kept in mind, although it should not
affect this implementation unless we allow users to create filesystem snapshots.

Ext4 also introduced journaling (jbd2). The journal must be updated
appropriately.

#### Performance

To improve performance we should implement a buffer cache, and optionally, read
ahead for small files. While doing so we must also keep in mind the memory usage
and have a reasonable cap on how much file data we want to hold in memory.

#### Features

Our current implementation will work with most ext4 filesystems for readonly
purposed. However, the following features are not supported yet:

-   Journal
-   Snapshotting
-   Extended Attributes
-   Hash Tree Directories
-   Meta Block Groups
-   Multiple Mount Protection
-   Bigalloc
