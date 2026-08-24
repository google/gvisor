// Copyright 2026 The gVisor Authors.
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

package kernel

import (
	"fmt"
	"io"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/fscheckpoint"
	fspb "gvisor.dev/gvisor/pkg/sentry/fscheckpoint/fscheckpoint_proto_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

// FSSaveOpts holds options to Kernel.FSSave.
type FSSaveOpts struct {
	// These correspond to files specified by the fscheckpoint package.
	// ManifestFile, MultiTarFile, and PagesMetadataFile are always required.
	// PagesFile is required iff Reflink is false.
	ManifestFile      io.WriteCloser
	MultiTarFile      io.WriteCloser
	PagesMetadataFile io.WriteCloser
	PagesFile         stateio.AsyncWriter

	// If Reflink is true, page contents are captured by cloning each
	// checkpointed filesystem's backing file into the corresponding entry of
	// FilestoreFiles with ioctl(FICLONE), rather than by copying them to
	// PagesFile. The i-th checkpointed filesystem in manifest order is cloned
	// into FilestoreFiles[i], and len(FilestoreFiles) must equal the number
	// of checkpointed filesystems. Cloning requires each destination file to
	// be on the same reflink-capable host filesystem as the corresponding
	// backing file.
	Reflink        bool
	FilestoreFiles []*fd.FD

	// RunscVersion is the runsc binary version.
	RunscVersion string

	// If ExitAfterSaving is true, all processes exit with status 0 before
	// FSSave returns, whether or not it returns a non-nil error.
	ExitAfterSaving bool

	// Paths is the list of paths inside the containers to save.
	// If empty, defaults to a single path "/" for all containers.
	Paths []checkpoint.ResourceID
}

// FSSave collects a filesystem checkpoint as specified by the fscheckpoint
// package. FSSave takes ownership of resources in opts.
func (k *Kernel) FSSave(ctx context.Context, opts *FSSaveOpts) error {
	defer func() {
		if opts.ManifestFile != nil {
			opts.ManifestFile.Close()
			opts.ManifestFile = nil
		}
		if opts.MultiTarFile != nil {
			opts.MultiTarFile.Close()
			opts.MultiTarFile = nil
		}
		if opts.PagesMetadataFile != nil {
			opts.PagesMetadataFile.Close()
			opts.PagesMetadataFile = nil
		}
		if opts.PagesFile != nil {
			opts.PagesFile.Close()
			opts.PagesFile = nil
		}
		for _, f := range opts.FilestoreFiles {
			f.Close()
		}
		opts.FilestoreFiles = nil
	}()
	pathsMap := fsCheckpointPathsMap(opts.Paths)

	k.Pause()
	defer k.Unpause()
	if opts.ExitAfterSaving {
		defer k.Kill(linux.WaitStatusExit(0)) // consistent with sentry/state.SaveOpts.Save
	}
	err := k.quiescePausedAnd(ctx, func() error {
		var (
			asyncPageSaveWg  sync.WaitGroup
			asyncPageSaveErr error
			apfs             *pgalloc.AsyncPagesFileSave
			mfOpts           pgalloc.SaveOpts
		)
		asyncPageSaveCleanup := cleanup.Make(func() {})
		defer asyncPageSaveCleanup.Clean()
		manifestVersion := uint64(1)
		if opts.Reflink {
			mfOpts.PagesInBackingFile = true
			manifestVersion = 2
		} else {
			asyncPageSaveWg.Add(1)
			var err error
			apfs, err = pgalloc.StartAsyncPagesFileSave(opts.PagesFile /* transfers ownership */, func(err error) {
				defer asyncPageSaveWg.Done()
				asyncPageSaveErr = err
			})
			opts.PagesFile = nil
			if err != nil {
				return fmt.Errorf("failed to start async page saving: %w", err)
			}
			asyncPageSaveCleanup = cleanup.Make(func() {
				apfs.MemoryFilesDone()
				asyncPageSaveWg.Wait()
			})
			mfOpts.PagesFile = apfs
		}

		manifest := &fspb.Manifest{
			Version:      manifestVersion,
			RunscVersion: opts.RunscVersion,
			PageSize:     hostarch.PageSize,
			Endian:       hostarch.EndianString(),
		}
		type tmpfsAndPrivateMemoryFile struct {
			fs *vfs.Filesystem
			mf *pgalloc.MemoryFile
		}
		resourceIDs := make(map[checkpoint.ResourceID]tmpfsAndPrivateMemoryFile)
		multiTarWriter := &countingWriter{w: opts.MultiTarFile}
		pagesMetadataWriter := &countingWriter{w: opts.PagesMetadataFile}
		prevTarOffset := uint64(0)
		prevPagesMetadataOffset := uint64(0)
		prevPagesOffset := uint64(0)
		fss := k.vfs.GetFilesystems()
		defer func() {
			for _, fs := range fss {
				fs.DecRef(ctx)
			}
		}()
		// TODO: NOLINT - fss is obtained by iterating a map, so its order -
		// and thus the order in which filesystems will be saved - is
		// effectively random. pgalloc.MemoryFile async page loading biases
		// toward MemoryFiles stored at lower offsets in the pages file. We
		// should save both filesystems and MemoryFiles in the order that they
		// were created, which is most likely to be the order in which they are
		// created after restore; in particular, this will be the case when the
		// same Kubernetes Pod spec is reused after restore.
		for _, fs := range fss {
			mf := tmpfs.MemoryFileOf(fs)
			if mf == nil {
				continue
			}
			resourceID := mf.ResourceID()
			// Exclude tmpfs filesystems backed by the main MemoryFile (which
			// have no ResourceID) since we currently have no way to save only
			// the contents of the main MemoryFile owned by a checkpointed
			// filesystem, and don't want to save all application memory.
			//
			// TODO: NOLINT - Support checkpointing tmpfs filesystems backed
			// by the main MemoryFile by implementing the ability to save a
			// subset of a pgalloc.MemoryFile, and using it to save only the
			// subset of each MemoryFile used by any checkpointed tmpfs
			// filesystem. This would also avoid saving MemoryFile pages that
			// are referenced by e.g. a previous MM.Pin() but no longer owned
			// by a regularFile; in such cases, the holder of the extra
			// reference won't be restored by filesystem checkpointing,
			// causing the referenced pages to be leaked. (As of this
			// writing, this leak is unlikely to be an issue in practice,
			// since the primary user of MM.Pin() is nvproxy, and the Nvidia
			// driver appears to reject pinning mappings of disk-backed
			// files.)
			if !resourceID.Ok() {
				continue
			}

			if !fsCheckpointPathsMatch(pathsMap, resourceID) {
				continue
			}
			if old, ok := resourceIDs[resourceID]; ok {
				return fmt.Errorf("pgalloc.MemoryFile restore ID %q is used by both tmpfs filesystem %p (MemoryFile %p) and tmpfs filesystem %p (MemoryFile %p)", resourceID, old.fs, old.mf, fs, mf)
			}
			resourceIDs[resourceID] = tmpfsAndPrivateMemoryFile{fs, mf}
			if log.IsLogging(log.Debug) {
				log.Debugf("Filesystem checkpoint saving tmpfs with resourceID %s", resourceID)
			}
			if err := mf.SaveTo(ctx, pagesMetadataWriter, &mfOpts); err != nil {
				return fmt.Errorf("failed to save MemoryFile with resourceID %s: %w", resourceID, err)
			}
			if opts.Reflink {
				idx := len(manifest.MemoryFiles)
				if idx >= len(opts.FilestoreFiles) {
					return fmt.Errorf("checkpoint has more than %d filesystems, but only %d filestore files were provided; filesystems may have been created concurrently with the checkpoint", len(opts.FilestoreFiles), len(opts.FilestoreFiles))
				}
				if err := unix.IoctlFileClone(opts.FilestoreFiles[idx].FD(), mf.FD()); err != nil {
					return fmt.Errorf("failed to clone backing file for %s: %w (reflink filesystem checkpoints require that the image path is on the same reflink-capable host filesystem as tmpfs filestore files)", resourceID, err)
				}
			}
			manifest.MemoryFiles = append(manifest.MemoryFiles, &fspb.MemoryFile{
				ResourceId:         toProtoResourceID(resourceID),
				PagesMetadataStart: prevPagesMetadataOffset,
				PagesMetadataEnd:   pagesMetadataWriter.count,
				PagesStart:         prevPagesOffset,
			})
			prevPagesMetadataOffset = pagesMetadataWriter.count
			if apfs != nil {
				prevPagesOffset = apfs.PagesFileOffset()
			}
			if err := tmpfs.FSCheckpointWrite(ctx, fs, multiTarWriter); err != nil {
				return fmt.Errorf("failed to write tmpfs with resourceID %s to multi-tar file: %w", resourceID, err)
			}
			manifest.Tmpfs = append(manifest.Tmpfs, &fspb.Tmpfs{
				ResourceId: toProtoResourceID(resourceID),
				TarStart:   prevTarOffset,
				TarEnd:     multiTarWriter.count,
			})
			prevTarOffset = multiTarWriter.count
		}
		if len(resourceIDs) == 0 {
			return fmt.Errorf("no checkpointable filesystems")
		}
		if opts.Reflink && len(resourceIDs) != len(opts.FilestoreFiles) {
			return fmt.Errorf("checkpointed %d filesystems, but %d filestore files were provided; filesystems may have been removed concurrently with the checkpoint", len(resourceIDs), len(opts.FilestoreFiles))
		}
		if apfs != nil {
			apfs.MemoryFilesDone()
		}
		bytes, err := proto.Marshal(manifest)
		if err != nil {
			return fmt.Errorf("failed to marshal manifest: %w", err)
		}
		if _, err := opts.ManifestFile.Write(bytes); err != nil {
			return fmt.Errorf("failed to write manifest file: %w", err)
		}
		// Close other writers while MemoryFile saving is in progress to
		// overlap their latencies.
		err = opts.ManifestFile.Close()
		opts.ManifestFile = nil
		if err != nil {
			return fmt.Errorf("failed to close manifest file: %w", err)
		}
		err = opts.MultiTarFile.Close()
		opts.MultiTarFile = nil
		if err != nil {
			return fmt.Errorf("failed to close multi-tar file: %w", err)
		}
		err = opts.PagesMetadataFile.Close()
		opts.PagesMetadataFile = nil
		if err != nil {
			return fmt.Errorf("failed to close pages metadata file: %w", err)
		}
		// Finally wait for MemoryFile saving to complete.
		asyncPageSaveCleanup.Release()()
		if asyncPageSaveErr != nil {
			return fmt.Errorf("failed to save MemoryFile pages: %w", asyncPageSaveErr)
		}
		return nil
	})
	k.fsSaveMu.Lock()
	defer k.fsSaveMu.Unlock()
	for _, c := range k.fsSaveWaiters {
		c <- err
	}
	k.fsSaveWaiters = nil
	return err
}

// fsCheckpointPathsMap converts a list of requested checkpoint paths to a set,
// applying the default of "/" in all containers.
func fsCheckpointPathsMap(paths []checkpoint.ResourceID) map[checkpoint.ResourceID]struct{} {
	if len(paths) == 0 {
		paths = []checkpoint.ResourceID{{Path: "/"}}
	}
	pathsMap := make(map[checkpoint.ResourceID]struct{}, len(paths))
	for _, p := range paths {
		pathsMap[p] = struct{}{}
	}
	return pathsMap
}

// fsCheckpointPathsMatch returns true if the filesystem with the given
// ResourceID is selected by the requested checkpoint paths.
func fsCheckpointPathsMatch(pathsMap map[checkpoint.ResourceID]struct{}, resourceID checkpoint.ResourceID) bool {
	if _, ok := pathsMap[resourceID]; ok {
		return true
	}
	if _, ok := pathsMap[checkpoint.ResourceID{Path: resourceID.Path}]; ok {
		return true
	}
	if _, ok := pathsMap[checkpoint.ResourceID{ContainerName: resourceID.ContainerName, Path: fscheckpoint.AllTmpfsPath}]; ok {
		return true
	}
	if _, ok := pathsMap[checkpoint.ResourceID{Path: fscheckpoint.AllTmpfsPath}]; ok {
		return true
	}
	return false
}

// FSCheckpointResources returns the ResourceIDs of the filesystems that would
// be included in a filesystem checkpoint with the given paths. The result's
// order is unspecified and may differ from checkpoint order; in particular,
// filesystem creation or destruction concurrent with a subsequent FSSave may
// change the set of checkpointed filesystems.
func (k *Kernel) FSCheckpointResources(ctx context.Context, paths []checkpoint.ResourceID) []checkpoint.ResourceID {
	pathsMap := fsCheckpointPathsMap(paths)
	fss := k.vfs.GetFilesystems()
	defer func() {
		for _, fs := range fss {
			fs.DecRef(ctx)
		}
	}()
	var ids []checkpoint.ResourceID
	for _, fs := range fss {
		mf := tmpfs.MemoryFileOf(fs)
		if mf == nil {
			continue
		}
		resourceID := mf.ResourceID()
		if !resourceID.Ok() {
			continue
		}
		if fsCheckpointPathsMatch(pathsMap, resourceID) {
			ids = append(ids, resourceID)
		}
	}
	return ids
}

type countingWriter struct {
	w     io.Writer
	count uint64
}

// Write implements io.Writer.Write.
func (cw *countingWriter) Write(src []byte) (int, error) {
	n, err := cw.w.Write(src)
	cw.count += uint64(n)
	return n, err
}

// WaitForFSSave waits for a call to k.FSSave() to complete, then returns the
// error returned by that call.
//
// This API is difficult to use without races, but is consistent with
// k.WaitForCheckpoint().
func (k *Kernel) WaitForFSSave() error {
	c := make(chan error, 1)
	k.fsSaveMu.Lock()
	k.fsSaveWaiters = append(k.fsSaveWaiters, c)
	k.fsSaveMu.Unlock()
	return <-c
}

// SignalAllFSSaveWaiters signals all FS save waiters with err.
func (k *Kernel) SignalAllFSSaveWaiters(err error) {
	k.fsSaveMu.Lock()
	defer k.fsSaveMu.Unlock()
	for _, c := range k.fsSaveWaiters {
		c <- err
	}
	k.fsSaveWaiters = nil
}

func toProtoResourceID(id checkpoint.ResourceID) *fspb.ResourceID {
	return &fspb.ResourceID{
		ContainerName: id.ContainerName,
		Path:          id.Path,
	}
}
