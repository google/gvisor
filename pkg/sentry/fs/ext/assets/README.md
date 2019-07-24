### Tiny Ext(2/3/4) Images

The images are of size 64Kb which supports 64 1k blocks and 16 inodes. This is
the smallest size mkfs.ext(2/3/4) works with.

These images were generated using the following commands.

```bash
fallocate -l 64K tiny.ext$VERSION
mkfs.ext$VERSION -j tiny.ext$VERSION
```

where `VERSION` is `2`, `3` or `4`.

You can mount it using:

```bash
sudo mount -o loop tiny.ext$VERSION $MOUNTPOINT
```

`file.txt`, `bigfile.txt` and `symlink.txt` were added to this image by just
mounting it and copying (while preserving links) those files to the mountpoint
directory using:

```bash
sudo cp -P {file.txt,symlink.txt,bigfile.txt} $MOUNTPOINT
```

The files in this directory mirror the contents and organisation of the files
stored in the image.

You can umount the filesystem using:

```bash
sudo umount $MOUNTPOINT
```
