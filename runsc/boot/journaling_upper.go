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

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/overlay"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs/journal"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
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

	mf, loaded, err := createPrivateMemoryFile(filestore, resourceID, c.containerID, c.l.fsRestore, jcfg.Enabled)
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
	l, cid, imageID := c.l, c.containerID, jcfg.ImageID
	if loaded {
		fsr := l.fsRestore
		return func(ctx context.Context, upper *vfs.Filesystem) error {
			l.activateJournalingUpperAsync(ctx, conf, cid, upper, imageID, func() error { return fsr.wait(cid) })
			return nil
		}, nil
	}
	return func(ctx context.Context, upper *vfs.Filesystem) error {
		if err := l.activateJournalingUpper(ctx, conf, cid, upper, imageID, false /* pause */); err != nil {
			return fmt.Errorf("failed to activate the journaling rootfs upper journal: %w", err)
		}
		return nil
	}, nil
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

// activateJournalingUpper prepares and starts journaling on upper after a
// restore, filesystem restore, or tar archive populated it.
func (l *Loader) activateJournalingUpper(ctx context.Context, conf *config.Config, cid string, upper *vfs.Filesystem, imageID string, pause bool) error {
	mf := tmpfs.MemoryFileOf(upper)
	if mf == nil {
		return fmt.Errorf("journaling rootfs upper is not a tmpfs filesystem")
	}
	if err := mf.AwaitLoadAll(); err != nil {
		return fmt.Errorf("failed to load journaling rootfs upper pages: %w", err)
	}
	if pause {
		l.k.Pause()
		defer l.k.Unpause()
	}
	j, err := tmpfs.PrepareJournal(ctx, upper, journalingUpperOpts(conf, imageID))
	if err != nil {
		return err
	}
	if conf.TestOnlyJournalingRootfsUpperFault == "activation" {
		j.Close()
		return fmt.Errorf("activation failure injected by --TESTONLY-journaling-rootfs-upper-fault")
	}
	if err := tmpfs.ActivateJournal(upper, j); err != nil {
		return err
	}
	log.Infof("Activated journaling rootfs upper journal for container %q", cid)
	return nil
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

type restoredJournalingUpper struct {
	conf    *config.Config
	cid     string
	upper   *vfs.Filesystem
	imageID string
}

type restoredJournalingUppers struct {
	l       *Loader
	targets []restoredJournalingUpper
	once    sync.Once
}

func (r *restoredJournalingUppers) release(ctx context.Context) {
	if r == nil {
		return
	}
	r.once.Do(func() {
		for _, t := range r.targets {
			t.upper.DecRef(ctx)
			r.l.journalingUpperWG.Done()
		}
	})
}

func (r *restoredJournalingUppers) activate(ctx context.Context) error {
	if r == nil {
		return nil
	}
	defer r.release(ctx)
	for _, t := range r.targets {
		if err := r.l.activateJournalingUpper(ctx, t.conf, t.cid, t.upper, t.imageID, true /* pause */); err != nil {
			return fmt.Errorf("container %q: %w", t.cid, err)
		}
	}
	return nil
}

// prepareJournalingUppersForRestore validates journaling settings and hides
// self-backed filestores before restored tasks start running, returning a
// handle whose activate method completes journal creation once background page
// loading finishes.
func (l *Loader) prepareJournalingUppersForRestore(ctx context.Context, containers []*containerInfo) (*restoredJournalingUppers, error) {
	res := &restoredJournalingUppers{l: l}
	for _, cont := range containers {
		if l.noRootContainer.enabled && cont.cid == l.root.cid {
			continue
		}
		if len(cont.goferMountConfs) == 0 || !cont.goferMountConfs[0].IsFilestorePresent() {
			continue
		}
		jcfg, err := specutils.JournalingRootfsUpper(cont.spec, cont.conf)
		if err != nil {
			res.release(ctx)
			return nil, fmt.Errorf("container %q: %w", cont.cid, err)
		}
		if !jcfg.Enabled {
			continue
		}

		upperVD, err := l.containerRootUpperVD(ctx, cont.cid)
		if err != nil {
			res.release(ctx)
			return nil, err
		}
		upperFS := upperVD.Mount().Filesystem()
		if cont.goferMountConfs[0].IsSelfBacked() {
			creds := auth.NewRootCredentials(l.k.RootUserNamespace())
			if err := syncSelfFilestoreWhiteout(ctx, l.k.VFS(), creds, upperFS, vfs.VirtualDentry{}, l.sandboxID); err != nil {
				upperVD.DecRef(ctx)
				res.release(ctx)
				return nil, fmt.Errorf("container %q: failed to create self-filestore whiteout: %w", cont.cid, err)
			}
		}
		upperFS.IncRef()
		upperVD.DecRef(ctx)
		l.journalingUpperWG.Add(1)
		res.targets = append(res.targets, restoredJournalingUpper{
			conf:    cont.conf,
			cid:     cont.cid,
			upper:   upperFS,
			imageID: jcfg.ImageID,
		})
	}
	if len(res.targets) == 0 {
		return nil, nil
	}
	return res, nil
}

// containerRootUpperVD returns a VirtualDentry for the root of the upper layer
// of container cid's root overlay, with a reference.
func (l *Loader) containerRootUpperVD(ctx context.Context, cid string) (vfs.VirtualDentry, error) {
	l.mu.Lock()
	ep := l.processes[execID{cid: cid}]
	var tg *kernel.ThreadGroup
	if ep != nil {
		tg = ep.tg
	}
	l.mu.Unlock()
	if tg == nil {
		return vfs.VirtualDentry{}, fmt.Errorf("container %q has no init process", cid)
	}
	mntns := tg.Leader().GetMountNamespace()
	if mntns == nil {
		return vfs.VirtualDentry{}, fmt.Errorf("container %q has no mount namespace", cid)
	}
	defer mntns.DecRef(ctx)
	root := mntns.Root(ctx)
	defer root.DecRef(ctx)
	upperVD := overlay.UpperRoot(root.Mount().Filesystem())
	if !upperVD.Ok() {
		return vfs.VirtualDentry{}, fmt.Errorf("rootfs of container %q is not an overlay with an upper layer", cid)
	}
	upperVD.IncRef()
	return upperVD, nil
}

// activateJournalingUpperAsync runs activateJournalingUpper for upper after the
// kernel starts and waitFn returns.
func (l *Loader) activateJournalingUpperAsync(ctx context.Context, conf *config.Config, cid string, upper *vfs.Filesystem, imageID string, waitFn func() error) {
	upper.IncRef()
	l.journalingUpperWG.Add(1)
	run := func(cancel bool) {
		defer l.journalingUpperWG.Done()
		defer upper.DecRef(ctx)
		if cancel {
			return
		}
		if err := waitFn(); err != nil {
			l.killForJournalingUpper(fmt.Errorf("container %q: populating the upper failed: %w", cid, err))
			return
		}
		if err := l.activateJournalingUpper(ctx, conf, cid, upper, imageID, true /* pause */); err != nil {
			l.killForJournalingUpper(fmt.Errorf("container %q: %w", cid, err))
		}
	}
	l.journalingUpperMu.Lock()
	defer l.journalingUpperMu.Unlock()
	if l.journalingUpperKernelStarted {
		go run(false)
		return
	}
	l.journalingUpperActivations = append(l.journalingUpperActivations, run)
}

// startJournalingUpperActivations starts activations scheduled before the
// kernel started.
func (l *Loader) startJournalingUpperActivations() {
	l.journalingUpperMu.Lock()
	fns := l.journalingUpperActivations
	l.journalingUpperActivations = nil
	l.journalingUpperKernelStarted = true
	l.journalingUpperMu.Unlock()
	for _, fn := range fns {
		go fn(false)
	}
}

func (l *Loader) cancelJournalingUpperActivations() {
	l.journalingUpperMu.Lock()
	fns := l.journalingUpperActivations
	l.journalingUpperActivations = nil
	l.journalingUpperMu.Unlock()
	for _, fn := range fns {
		fn(true)
	}
}

func (l *Loader) awaitJournalingUppersOnCleanExit(ws uint32) uint32 {
	if linux.WaitStatus(ws) == 0 {
		l.journalingUpperWG.Wait()
		if l.journalingUpperFailed.Load() {
			return uint32(linux.WaitStatusTerminationSignal(linux.SIGKILL))
		}
	}
	return ws
}

func (l *Loader) killForJournalingUpper(err error) {
	log.Warningf("Killing the sandbox: failed to activate a journaling rootfs upper journal: %v.", err)
	l.journalingUpperFailed.Store(true)
	l.k.Kill(linux.WaitStatusTerminationSignal(linux.SIGKILL))
	l.stopIfKilled()
}
