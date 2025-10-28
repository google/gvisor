// Copyright 2025 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tmpfs

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// UntarUpperLayer creates the corresponding dentry and its children from the
// given snapshot tar file.
func (fs *filesystem) UntarUpperLayer(ctx context.Context, inFile *os.File) error {
	tr := tar.NewReader(inFile)

	fs.mu.Lock()
	defer fs.mu.Unlock()

	return fs.readFromTar(ctx, tr)
}

// readFromTar creates the corresponding dentry and its children from the given
// tar reader.
//
// Preconditions:
//   - filesystem.mu must be locked.
func (fs *filesystem) readFromTar(ctx context.Context, tr *tar.Reader) error {
	pathToInode := map[string]*inode{}
	directoryToHeader := map[string]*tar.Header{}
	fileToHeader := map[string]*tar.Header{}
	symlinkToHeader := map[string]*tar.Header{}
	linkToHeader := map[string]*tar.Header{}
	fileToContent := map[string]*bytes.Buffer{}
	for {
		header, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			directoryToHeader[header.Name] = header
		case tar.TypeReg:
			var buffer bytes.Buffer
			n, err := io.Copy(&buffer, tr)
			if err != nil {
				return fmt.Errorf("failed to read file content: %w", err)
			}
			if n != header.Size {
				return fmt.Errorf("failed to read all file content, got %d bytes, want %d", n, header.Size)
			}
			if header.Size > 0 {
				fileToContent[header.Name] = &buffer
			}
			fileToHeader[header.Name] = header
		case tar.TypeFifo, tar.TypeBlock, tar.TypeChar:
			fileToHeader[header.Name] = header
		case tar.TypeSymlink:
			symlinkToHeader[header.Name] = header
		case tar.TypeLink:
			linkToHeader[header.Name] = header
		default:
			return fmt.Errorf("readfrom unsupported file type %v for %v", header.Typeflag, header.Name)
		}
	}
	// Re-create all directories.
	for path, hdr := range directoryToHeader {
		if _, err := fs.mkdirFromTar(hdr, pathToInode, directoryToHeader); err != nil {
			return fmt.Errorf("failed to make directory %v: %w", path, err)
		}
	}
	// Re-create all regular files, FIFOs, block devices, and character devices.
	for path, hdr := range fileToHeader {
		if err := fs.mknodFromTar(ctx, hdr, pathToInode, fileToContent); err != nil {
			return fmt.Errorf("failed to make file %v: %w", path, err)
		}
	}
	// Re-create all symlinks.
	for path, hdr := range symlinkToHeader {
		if err := fs.symlinkFromTar(hdr, pathToInode); err != nil {
			return fmt.Errorf("failed to make symlink %v: %w", path, err)
		}
	}
	// Re-create all hard links.
	// Note that hard links are created after the rest of the supported file types
	// since they need to link to existing inodes.
	for path, hdr := range linkToHeader {
		if err := fs.linkFromTar(hdr, pathToInode); err != nil {
			return fmt.Errorf("failed to make hard link %v: %w", path, err)
		}
	}
	return nil
}

// mkdirFromTar recursively creates a directory and its parent directories
// using the provided headers.
func (fs *filesystem) mkdirFromTar(hdr *tar.Header, pathToInode map[string]*inode, pathToHeader map[string]*tar.Header) (*inode, error) {
	path := hdr.Name
	if ino, ok := pathToInode[hdr.Name]; ok {
		return ino, nil
	}
	if hdr.Name == "./" {
		ino := fs.root.inode
		ino.uid.Store(uint32(hdr.Uid))
		ino.gid.Store(uint32(hdr.Gid))
		ino.mode.Store(uint32(hdr.Mode) | linux.S_IFDIR)
		ino.mtime.Store(hdr.ModTime.UnixNano())
		pathToInode[hdr.Name] = ino
		return ino, nil
	}
	dir, name := filepath.Split(strings.TrimSuffix(path, "/"))
	parentInode, ok := pathToInode[dir]
	if !ok {
		parentHdr, ok := pathToHeader[dir]
		if !ok {
			return nil, fmt.Errorf("failed to find header for %v", dir)
		}
		var err error
		// Recursively create the parent directories.
		if parentInode, err = fs.mkdirFromTar(parentHdr, pathToInode, pathToHeader); err != nil {
			return nil, err
		}
	}
	if parentInode.nlink.Load() == maxLinks {
		return nil, fmt.Errorf("maximum number of links reached for %v", dir)
	}
	parentDir, ok := parentInode.impl.(*directory)
	if !ok {
		return nil, fmt.Errorf("parent inode at %v is not a directory", dir)
	}
	parentDir.inode.incLinksLocked()
	childDir := fs.newDirectory(auth.KUID(hdr.Uid), auth.KGID(hdr.Gid), linux.FileMode(hdr.Mode), parentDir)
	childDir.inode.mtime.Store(hdr.ModTime.UnixNano())
	parentDir.insertChildLocked(&childDir.dentry, name)
	pathToInode[path] = childDir.dentry.inode
	return childDir.dentry.inode, nil
}

// mknodFromTar creates a regular file,FIFO, block device, or character device file using
// the provided header. It also writes the file content to the corresponding regular file if it
// exists.
func (fs *filesystem) mknodFromTar(ctx context.Context, hdr *tar.Header, pathToInode map[string]*inode, pathToContent map[string]*bytes.Buffer) error {
	dir, name := filepath.Split(hdr.Name)
	parentInode, ok := pathToInode[dir]
	if !ok {
		return fmt.Errorf("parent directory %v does not exist", dir)
	}
	parentDir, ok := parentInode.impl.(*directory)
	if !ok {
		return fmt.Errorf("%v is not a directory", dir)
	}
	var childInode *inode
	switch hdr.Typeflag {
	case tar.TypeReg:
		childInode = fs.newRegularFile(auth.KUID(hdr.Uid), auth.KGID(hdr.Gid), linux.FileMode(hdr.Mode), parentDir)
	case tar.TypeFifo:
		childInode = fs.newNamedPipe(auth.KUID(hdr.Uid), auth.KGID(hdr.Gid), linux.FileMode(hdr.Mode), parentDir)
	case tar.TypeBlock:
		childInode = fs.newDeviceFileLocked(auth.KUID(hdr.Uid), auth.KGID(hdr.Gid), linux.FileMode(hdr.Mode|linux.S_IFBLK), uint32(hdr.Devmajor), uint32(hdr.Devminor), parentDir)
	case tar.TypeChar:
		childInode = fs.newDeviceFileLocked(auth.KUID(hdr.Uid), auth.KGID(hdr.Gid), linux.FileMode(hdr.Mode|linux.S_IFCHR), uint32(hdr.Devmajor), uint32(hdr.Devminor), parentDir)
	default:
		return fmt.Errorf("mknod unsupported file type %v for %v", hdr.Typeflag, hdr.Name)
	}
	childInode.mtime.Store(hdr.ModTime.UnixNano())
	child := fs.newDentry(childInode)
	parentDir.insertChildLocked(child, name)
	pathToInode[hdr.Name] = childInode

	// Write file contents to the corresponding regular files if they exist.
	if buf, ok := pathToContent[hdr.Name]; ok {
		if err := fs.writeTo(ctx, hdr.Name, pathToInode, int64(len(buf.Bytes())), buf); err != nil {
			return fmt.Errorf("failed to write file content for %v: %w", hdr.Name, err)
		}
	}

	return nil
}

// linkFromTar creates a hard link from the given tar header.
func (fs *filesystem) linkFromTar(hdr *tar.Header, pathToInode map[string]*inode) error {
	dir, name := filepath.Split(hdr.Name)
	parentInode, ok := pathToInode[dir]
	if !ok {
		return fmt.Errorf("parent directory %v does not exist", dir)
	}
	parentDir, ok := parentInode.impl.(*directory)
	if !ok {
		return fmt.Errorf("%v is not a directory", dir)
	}
	childInode, ok := pathToInode[hdr.Linkname]
	if !ok {
		return fmt.Errorf("child inode %v does not exist", hdr.Linkname)
	}
	if childInode.nlink.Load() == maxLinks {
		return fmt.Errorf("maximum number of links reached for %s", hdr.Linkname)
	}
	childInode.incLinksLocked()
	child := fs.newDentry(childInode)
	parentDir.insertChildLocked(child, name)
	pathToInode[hdr.Name] = child.inode
	return nil
}

// symlinkFromTar creates a symlink from the given tar header.
func (fs *filesystem) symlinkFromTar(hdr *tar.Header, pathToInode map[string]*inode) error {
	dir, name := filepath.Split(hdr.Name)
	parentInode, ok := pathToInode[dir]
	if !ok {
		return fmt.Errorf("parent directory %v does not exist", dir)
	}
	if len(hdr.Linkname) >= shortSymlinkLen {
		return fmt.Errorf("symlink %v is too long", hdr.Linkname)
	}
	parentDir, ok := parentInode.impl.(*directory)
	if !ok {
		return fmt.Errorf("%v is not a directory", dir)
	}
	child := fs.newDentry(fs.newSymlink(auth.KUID(hdr.Uid), auth.KGID(hdr.Gid), 0777, hdr.Linkname, parentDir))
	child.inode.mtime.Store(hdr.ModTime.UnixNano())
	parentDir.insertChildLocked(child, name)
	pathToInode[hdr.Name] = child.inode
	return nil
}

func (fs *filesystem) writeTo(ctx context.Context, path string, pathToInode map[string]*inode, size int64, buf *bytes.Buffer) error {
	i, ok := pathToInode[path]
	if !ok {
		return fmt.Errorf("failed to find inode for %v", path)
	}
	rf := i.impl.(*regularFile)
	rf.inode.mu.Lock()
	defer rf.inode.mu.Unlock()
	src := usermem.BytesIOSequence(buf.Bytes())
	rw := getRegularFileReadWriter(rf, 0, 0)
	n, err := src.CopyInTo(ctx, rw)
	if err != nil {
		return fmt.Errorf("failed to write file content: %w", err)
	}
	if n != size {
		return fmt.Errorf("failed to write all file content to %v, got %d bytes, want %d", path, n, size)
	}
	putRegularFileReadWriter(rw)
	return nil
}

// TarUpperLayer implements vfs.TarSerializer.TarUpperLayer.
func (fs *filesystem) TarUpperLayer(ctx context.Context, outFD *os.File) error {
	tw := tar.NewWriter(outFD)

	fs.mu.RLock()
	defer fs.mu.RUnlock()

	err := fs.root.writeToTar(ctx, tw, ".", make(map[uint64]string))
	if err != nil {
		return fmt.Errorf("failed to write dentry to tar: %w", err)
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("failed to close tar writer: %w", err)
	}

	return nil
}

// writeToTar recursively writes a dentry and its children to the tar archive.
func (d *dentry) writeToTar(ctx context.Context, tw *tar.Writer, baseDir string, inoToPath map[uint64]string) error {
	path := baseDir
	if d.name != "" {
		path = path + "/" + d.name
	}
	header, err := d.createTarHeader(path, inoToPath)
	if err != nil {
		return fmt.Errorf("failed to create tar header for %q: %w", path, err)
	}
	if header == nil {
		return nil
	}

	if err := tw.WriteHeader(header); err != nil {
		return fmt.Errorf("failed to write tar header for %q: %w", path, err)
	}

	// If the file is a hard link, we don't need to write its content.
	if header.Typeflag == tar.TypeLink {
		return nil
	}

	switch impl := d.inode.impl.(type) {
	case *directory:
		for _, child := range impl.childMap {
			if err := child.writeToTar(ctx, tw, path, inoToPath); err != nil {
				return err
			}
		}
	case *regularFile:
		if err := impl.writeToTar(ctx, tw); err != nil {
			return fmt.Errorf("failed to write file content for %q: %w", path, err)
		}
	}

	return nil
}

// createTarHeader creates a tar header for the given dentry.
func (d *dentry) createTarHeader(path string, inoToPath map[uint64]string) (*tar.Header, error) {
	if d.isSelfFilestoreWhiteout() {
		// Skip the self filestore whiteout.
		return nil, nil
	}

	header := &tar.Header{
		Name:    path,
		Mode:    int64(d.inode.mode.Load() & ^uint32(linux.S_IFMT)),
		Uid:     int(d.inode.uid.Load()),
		Gid:     int(d.inode.gid.Load()),
		ModTime: time.Unix(0, d.inode.mtime.Load()),
	}
	// Hard link: Check if the inode has already been written to the tar archive.
	if existingPath, ok := inoToPath[d.inode.ino]; ok {
		header.Typeflag = tar.TypeLink
		header.Linkname = existingPath
		return header, nil
	}

	switch impl := d.inode.impl.(type) {
	case *directory:
		header.Typeflag = tar.TypeDir
		header.Name += "/"
	case *regularFile:
		header.Typeflag = tar.TypeReg
		header.Size = int64(impl.size.Load())
	case *symlink:
		header.Typeflag = tar.TypeSymlink
		header.Linkname = impl.target
	case *namedPipe:
		header.Typeflag = tar.TypeFifo
	case *deviceFile:
		if impl.kind == vfs.BlockDevice {
			header.Typeflag = tar.TypeBlock
		} else {
			header.Typeflag = tar.TypeChar
		}
		header.Devmajor = int64(impl.major)
		header.Devminor = int64(impl.minor)
	case *socketFile:
		// This is consistent with the behavior of tar(1).
		log.Warningf("Skipping socket file %q while generating tar archive", path)
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported file type for %q", path)
	}
	inoToPath[d.inode.ino] = path
	return header, nil
}

// writeToTar writes the content of a regular file to the tar archive.
func (rf *regularFile) writeToTar(ctx context.Context, tw *tar.Writer) error {
	// Note that regularFileReadWriter.ReadToBlocks() does not lock inode.mu. So
	// it is safe to lock here to ensure no concurrent writes occur.
	rf.inode.mu.Lock()
	defer rf.inode.mu.Unlock()
	data := make([]byte, rf.size.RacyLoad())
	dst := usermem.BytesIOSequence(data)
	rw := getRegularFileReadWriter(rf, 0, 0)
	n, err := dst.CopyOutFrom(ctx, rw)
	putRegularFileReadWriter(rw)
	if err != nil && err != io.EOF {
		return fmt.Errorf("failed to read file content: %w", err)
	}
	if n != int64(len(data)) {
		return fmt.Errorf("failed to read all file content, got %d bytes, want %d", n, len(data))
	}
	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("failed to write file content to tar: %w", err)
	}
	return nil
}
