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
	"fmt"
	"io"
	"os"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

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
