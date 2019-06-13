### Tiny Ext4 Image

The image is of size 64Kb which supports 64 1k blocks and 16 inodes. This is the
smallest size mkfs.ext4 works with.

This image was generated using the following commands.

```bash
fallocate -l 64K tiny.ext4
mkfs.ext4 -j tiny.ext4
```

You can mount it on a directory (lets say `mountpoint` for now) by:

```bash
sudo mount -o loop tiny.ext4 mountpoint
```

`file.txt` and `symlink.txt` were added to this image by just mounting it and
copying (while preserving links) those files to the mountpoint directory.
