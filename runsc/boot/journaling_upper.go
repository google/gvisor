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

package boot

import (
	"errors"
	"fmt"
	"os"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs/journal"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
	"gvisor.dev/gvisor/runsc/version"
)

func journalingUpperOpts(conf *config.Config, imageID string) journal.Options {
	return journal.Options{
		BuildID:    version.Version(),
		ImageID:    imageID,
		RegionSize: conf.TestOnlyJournalingRootfsUpperRegionSize,
	}
}

// configureOverlayFilestore initializes tmpfsOpts.MemoryFile (and any journal
// options) from filestore. It takes ownership of filestore. For a populated
// journaled rootfs upper (tar or filesystem restore), it returns a post-mount
// activation callback.
func (c *containerMounter) configureOverlayFilestore(conf *config.Config, dst string, filestore *os.File, hasTar bool, tmpfsOpts *tmpfs.FilesystemOpts) (func(context.Context, *vfs.Filesystem) error, error) {
	resourceID := checkpoint.ResourceID{ContainerName: c.containerName, Path: dst}
	var jcfg specutils.JournalingRootfsUpperConfig
	if dst == "/" {
		var err error
		jcfg, err = specutils.JournalingRootfsUpper(c.spec, conf)
		if err != nil {
			filestore.Close()
			return nil, err
		}
	}

	populate := c.l.fsRestore != nil || hasTar
	if jcfg.ImportPath != "" {
		if populate {
			filestore.Close()
			return nil, fmt.Errorf("journaling rootfs upper import cannot be used with filesystem restore or rootfs upper tar")
		}
		mf, j, st, err := openImportedJournalingUpper(filestore, conf, jcfg, resourceID)
		if err != nil {
			return nil, fmt.Errorf("failed to import journaling rootfs upper: %w", err)
		}
		tmpfsOpts.MemoryFile = mf
		tmpfsOpts.Journal = j
		tmpfsOpts.JournalState = st
		return nil, nil
	}
	if jcfg.Enabled && !populate {
		mf, j, err := createJournalingUpper(filestore, conf, jcfg, resourceID)
		if err != nil {
			return nil, fmt.Errorf("failed to create journaling rootfs upper: %w", err)
		}
		tmpfsOpts.MemoryFile = mf
		tmpfsOpts.Journal = j
		return nil, nil
	}

	mf, _, err := createPrivateMemoryFile(filestore, resourceID, c.containerID, c.l.fsRestore, jcfg.Enabled)
	if err != nil {
		return nil, fmt.Errorf("failed to create memory file for overlay: %v", err)
	}
	sourceTar, err := c.l.fsRestore.tmpfsSourceTar(resourceID, c.containerID)
	if err != nil {
		mf.Destroy()
		return nil, fmt.Errorf("failed to get tar archive from filesystem checkpoint: %w", err)
	}
	tmpfsOpts.MemoryFile = mf
	if sourceTar != nil {
		log.Infof("Loading filesystem checkpoint tree for %q", resourceID)
		tmpfsOpts.SourceTar = sourceTar
		tmpfsOpts.SourceTarFSCheckpoint = true
	}
	if !jcfg.Enabled {
		return nil, nil
	}
	return nil, fmt.Errorf("populated journaling rootfs upper is not yet supported")
}

// createJournalingUpper initializes a fresh journaled MemoryFile on filestore.
// It takes ownership of filestore.
func createJournalingUpper(filestore *os.File, conf *config.Config, jcfg specutils.JournalingRootfsUpperConfig, resourceID checkpoint.ResourceID) (*pgalloc.MemoryFile, *journal.Journal, error) {
	mf, err := pgalloc.NewMemoryFile(filestore, journalingMemoryFileOpts(resourceID, false /* keepContents */))
	if err != nil {
		filestore.Close()
		return nil, nil, err
	}
	j, err := journal.Create(mf, journalingUpperOpts(conf, jcfg.ImageID))
	if err != nil {
		mf.Destroy()
		return nil, nil, err
	}
	log.Infof("Created journaling rootfs upper for %v", resourceID)
	return mf, j, nil
}

// openImportedJournalingUpper replays an imported journaled rootfs upper
// filestore and adopts its pages into a new MemoryFile. If jcfg.Enabled is
// true, it also returns an open Journal to continue journaling into filestore.
// It takes ownership of filestore.
func openImportedJournalingUpper(filestore *os.File, conf *config.Config, jcfg specutils.JournalingRootfsUpperConfig, resourceID checkpoint.ResourceID) (*pgalloc.MemoryFile, *journal.Journal, *journal.State, error) {
	mf, err := pgalloc.NewMemoryFile(filestore, journalingMemoryFileOpts(resourceID, true /* keepContents */))
	if err != nil {
		filestore.Close()
		return nil, nil, nil, err
	}
	j, st, err := journal.Open(mf, journalingUpperOpts(conf, jcfg.ImageID), jcfg.Enabled)
	if err != nil {
		mf.Destroy()
		if errors.Is(err, journal.ErrIncomplete) {
			return nil, nil, nil, fmt.Errorf("imported rootfs upper journal at %q is incomplete: %w", jcfg.ImportPath, err)
		}
		return nil, nil, nil, err
	}
	log.Infof("Imported journaling rootfs upper %q (keepJournal=%t) with %d inodes and %d filestore ranges", jcfg.ImportPath, jcfg.Enabled, len(st.Inodes), len(st.UsedRanges()))
	return mf, j, st, nil
}

// journalingMemoryFileOpts returns the options of a MemoryFile that backs a
// journaled or imported rootfs upper, with DecommitOnDestroy false so pages
// survive sandbox exit.
func journalingMemoryFileOpts(resourceID checkpoint.ResourceID, keepContents bool) pgalloc.MemoryFileOpts {
	return pgalloc.MemoryFileOpts{
		DiskBackedFile:          true,
		KeepFileContents:        keepContents,
		DisableMemoryAccounting: true,
		DisableIMAWorkAround:    true,
		ResourceID:              resourceID,
	}
}

// syncSelfFilestoreWhiteout hides this sandbox's self-backed filestore in
// upperFS without altering upperFS's root directory timestamps, and removes any
// imported self-filestore whiteouts from earlier sandboxes that do not exist on
// lowerRootVD.
func syncSelfFilestoreWhiteout(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, upperFS *vfs.Filesystem, lowerRootVD vfs.VirtualDentry, sandboxID string) error {
	selfName := sentryapi.SelfFilestoreName(sandboxID)
	var remove []string
	if lowerRootVD.Ok() {
		for _, name := range tmpfs.SelfFilestoreWhiteouts(upperFS) {
			if name == selfName {
				continue
			}
			d, err := vfsObj.GetDentryAt(ctx, creds, &vfs.PathOperation{
				Root:  lowerRootVD,
				Start: lowerRootVD,
				Path:  fspath.Parse(name),
			}, &vfs.GetDentryOptions{})
			if err == nil {
				d.DecRef(ctx)
				continue
			}
			if linuxerr.Equals(linuxerr.ENOENT, err) {
				remove = append(remove, name)
			}
		}
	}
	return tmpfs.SyncSelfFilestoreWhiteouts(ctx, upperFS, selfName, remove)
}
