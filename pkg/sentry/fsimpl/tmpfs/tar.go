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
	"unicode/utf8"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// tarRead creates the corresponding dentry and its children from the given
// snapshot tar file.
func (fs *filesystem) tarRead(ctx context.Context, src io.Reader, cb tarReaderCallbacks) error {
	tr := tar.NewReader(src)

	fs.mu.Lock()
	defer fs.mu.Unlock()

	return fs.readFromTar(ctx, tr, cb)
}

// readFromTar creates the corresponding dentry and its children from the given
// tar reader.
//
// Preconditions:
//   - filesystem.mu must be locked.
func (fs *filesystem) readFromTar(ctx context.Context, tr *tar.Reader, cb tarReaderCallbacks) error {
	pathToInode := map[string]*inode{}
	directoryToHeader := map[string]*tar.Header{}
	fileToHeader := map[string]*tar.Header{}
	symlinkToHeader := map[string]*tar.Header{}
	linkToHeader := map[string]*tar.Header{}
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
			if err := cb.regularFileRead(ctx, header, tr); err != nil {
				return err
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
		if err := fs.mknodFromTar(ctx, hdr, pathToInode, cb); err != nil {
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

// Tar archives store xattrs with the "SCHILY.xattr." prefix in PAXRecords.
const paxXattrPrefix = "SCHILY.xattr."

// setXattrsFromPAXRecords extracts xattrs from hdr.PAXRecords and sets them
// on the inode.
func (i *inode) setXattrsFromPAXRecords(hdr *tar.Header) {
	var xattrs map[string]string
	for k, v := range hdr.PAXRecords {
		if strings.HasPrefix(k, paxXattrPrefix) {
			if xattrs == nil {
				xattrs = make(map[string]string)
			}
			xattrs[strings.TrimPrefix(k, paxXattrPrefix)] = v
		}
	}
	if len(xattrs) > 0 {
		i.xattrs.SetRawXattrs(xattrs)
	}
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
		ino.setXattrsFromPAXRecords(hdr)
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
	childDir, err := fs.newDirectory(auth.KUID(hdr.Uid), auth.KGID(hdr.Gid), linux.FileMode(hdr.Mode), parentDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create new directory inode: %v", err)
	}
	parentDir.inode.incLinksLocked()
	childDir.inode.mtime.Store(hdr.ModTime.UnixNano())
	childDir.inode.setXattrsFromPAXRecords(hdr)
	parentDir.insertChildLocked(&childDir.dentry, name)
	pathToInode[path] = childDir.dentry.inode
	return childDir.dentry.inode, nil
}

// mknodFromTar creates a regular file,FIFO, block device, or character device file using
// the provided header. It also writes the file content to the corresponding regular file if it
// exists.
func (fs *filesystem) mknodFromTar(ctx context.Context, hdr *tar.Header, pathToInode map[string]*inode, cb tarReaderCallbacks) error {
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
	var err error
	switch hdr.Typeflag {
	case tar.TypeReg:
		childInode, err = fs.newRegularFile(auth.KUID(hdr.Uid), auth.KGID(hdr.Gid), linux.FileMode(hdr.Mode), parentDir)
	case tar.TypeFifo:
		childInode, err = fs.newNamedPipe(auth.KUID(hdr.Uid), auth.KGID(hdr.Gid), linux.FileMode(hdr.Mode), parentDir)
	case tar.TypeBlock:
		childInode, err = fs.newDeviceFileLocked(auth.KUID(hdr.Uid), auth.KGID(hdr.Gid), linux.FileMode(hdr.Mode|linux.S_IFBLK), uint32(hdr.Devmajor), uint32(hdr.Devminor), parentDir)
	case tar.TypeChar:
		childInode, err = fs.newDeviceFileLocked(auth.KUID(hdr.Uid), auth.KGID(hdr.Gid), linux.FileMode(hdr.Mode|linux.S_IFCHR), uint32(hdr.Devmajor), uint32(hdr.Devminor), parentDir)
	default:
		return fmt.Errorf("mknod unsupported file type %v for %v", hdr.Typeflag, hdr.Name)
	}
	if err != nil {
		return err
	}
	childInode.mtime.Store(hdr.ModTime.UnixNano())
	childInode.setXattrsFromPAXRecords(hdr)
	child := fs.newDentry(childInode)
	parentDir.insertChildLocked(child, name)
	pathToInode[hdr.Name] = childInode

	// Write file contents to the corresponding regular files.
	if rf, _ := childInode.impl.(*regularFile); rf != nil {
		if err := cb.regularFileSetContents(ctx, hdr, rf); err != nil {
			return err
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
	parentDir, ok := parentInode.impl.(*directory)
	if !ok {
		return fmt.Errorf("%v is not a directory", dir)
	}
	// Linux allocates a page to store symlink targets that have length larger
	// than shortSymlinkLen. Mirror SymlinkAt's accounting so creation and
	// teardown stay balanced; otherwise (*inode).decRef's matching
	// unaccountPages(1) underflows fs.pagesUsed and panics on teardown.
	// See mm/shmem.c:shmem_symlink().
	if len(hdr.Linkname) >= shortSymlinkLen {
		if !fs.accountPages(1) {
			return fmt.Errorf("tmpfs: insufficient space to account for symlink target %q", hdr.Name)
		}
	}
	childInode, err := fs.newSymlink(auth.KUID(hdr.Uid), auth.KGID(hdr.Gid), 0777, hdr.Linkname, parentDir)
	if err != nil {
		return fmt.Errorf("failed to create inode from tar: %v", err)
	}
	child := fs.newDentry(childInode)
	child.inode.mtime.Store(hdr.ModTime.UnixNano())
	child.inode.setXattrsFromPAXRecords(hdr)
	parentDir.insertChildLocked(child, name)
	pathToInode[hdr.Name] = child.inode
	return nil
}

type tarReaderCallbacks interface {
	// regularFileRead reads information about the regular file with header hdr
	// from tr.
	regularFileRead(ctx context.Context, hdr *tar.Header, tr *tar.Reader) error

	// regularFileSetContents sets the contents and size of rf, using what was
	// previously read for hdr.
	regularFileSetContents(ctx context.Context, hdr *tar.Header, rf *regularFile) error
}

// tarDefaultReaderCallbacks implements tarReaderCallbacks by reading regular
// file contents from the tar archive.
type tarDefaultReaderCallbacks struct {
	headerToContent map[*tar.Header]*bytes.Buffer
}

func (cb *tarDefaultReaderCallbacks) regularFileRead(ctx context.Context, hdr *tar.Header, tr *tar.Reader) error {
	var buf bytes.Buffer
	n, err := io.Copy(&buf, tr)
	if err != nil {
		return fmt.Errorf("failed to read file content: %w", err)
	}
	if n != hdr.Size {
		return fmt.Errorf("failed to read all file content, got %d bytes, want %d", n, hdr.Size)
	}
	if hdr.Size > 0 {
		cb.headerToContent[hdr] = &buf
	}
	return nil
}

func (cb *tarDefaultReaderCallbacks) regularFileSetContents(ctx context.Context, hdr *tar.Header, rf *regularFile) error {
	buf, ok := cb.headerToContent[hdr]
	if !ok {
		return nil
	}
	rf.inode.mu.Lock()
	defer rf.inode.mu.Unlock()
	src := usermem.BytesIOSequence(buf.Bytes())
	rw := getRegularFileReadWriter(rf, 0, 0)
	n, err := src.CopyInTo(ctx, rw)
	if err != nil {
		return fmt.Errorf("failed to write file content: %w", err)
	}
	if size := int64(len(buf.Bytes())); n != size {
		return fmt.Errorf("failed to write all file content to %v, got %d bytes, want %d", hdr.Name, n, size)
	}
	putRegularFileReadWriter(rw)
	return nil
}

// TarUpperLayer implements vfs.TarSerializer.TarUpperLayer.
func (fs *filesystem) TarUpperLayer(ctx context.Context, outFD *os.File) error {
	return fs.tarWrite(ctx, outFD, tarDefaultWriterCallbacks{})
}

func (fs *filesystem) tarWrite(ctx context.Context, dst io.Writer, cb tarWriterCallbacks) error {
	tw := tar.NewWriter(dst)

	fs.mu.RLock()
	defer fs.mu.RUnlock()

	err := fs.root.writeToTar(ctx, tw, ".", make(map[uint64]string), cb)
	if err != nil {
		return fmt.Errorf("failed to write dentry to tar: %w", err)
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("failed to close tar writer: %w", err)
	}

	return nil
}

// writeToTar recursively writes a dentry and its children to the tar archive.
func (d *dentry) writeToTar(ctx context.Context, tw *tar.Writer, baseDir string, inoToPath map[uint64]string, cb tarWriterCallbacks) error {
	path := baseDir
	if d.name != "" {
		path = path + "/" + d.name
	}
	header, err := d.createTarHeader(path, inoToPath, cb)
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
			if err := child.writeToTar(ctx, tw, path, inoToPath, cb); err != nil {
				return err
			}
		}
	case *regularFile:
		if err := cb.regularFileWrite(ctx, impl, tw); err != nil {
			return fmt.Errorf("failed to write file content for %q: %w", path, err)
		}
	}

	return nil
}

// createTarHeader creates a tar header for the given dentry.
func (d *dentry) createTarHeader(path string, inoToPath map[uint64]string, cb tarWriterCallbacks) (*tar.Header, error) {
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
		header.Size = cb.regularFileSize(impl)
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

	// Serialize xattrs to PAXRecords.
	if xattrs := d.inode.xattrs.RawXattrs(); len(xattrs) > 0 {
		header.PAXRecords = make(map[string]string, len(xattrs))
		for k, v := range xattrs {
			// PaxRecords require that key and value are non-empty UTF-8 strings and
			// that the key does not contain '='.
			if strings.Contains(k, "=") {
				log.Warningf("Skipping xattr (k=%q, v=%q) for file %q while generating tar archive because key contains '='", k, v, path)
				continue
			}
			if k == "" || v == "" {
				log.Warningf("Skipping xattr (k=%q, v=%q) for file %q while generating tar archive because key or value is empty", k, v, path)
				continue
			}
			if !utf8.ValidString(k) || !utf8.ValidString(v) {
				log.Warningf("Skipping xattr (k=%q, v=%q) for file %q while generating tar archive because value is not a valid UTF-8 string", k, v, path)
				continue
			}
			header.PAXRecords[paxXattrPrefix+k] = v
		}
	}

	inoToPath[d.inode.ino] = path
	return header, nil
}

type tarWriterCallbacks interface {
	// regularFileSize returns the size of the given regular file as written to
	// the tar archive.
	regularFileSize(rf *regularFile) int64

	// regularFileWrite writes the contents of the given regular file to tw.
	regularFileWrite(ctx context.Context, rf *regularFile, tw *tar.Writer) error
}

// tarDefaultWriterCallbacks implements tarWriterCallbacks by writing regular
// file contents to the tar archive.
type tarDefaultWriterCallbacks struct{}

func (tarDefaultWriterCallbacks) regularFileSize(rf *regularFile) int64 {
	return int64(rf.size.Load())
}

func (tarDefaultWriterCallbacks) regularFileWrite(ctx context.Context, rf *regularFile, tw *tar.Writer) error {
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
