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
	"slices"

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
// options) from filestore. It takes ownership of filestore. For a journaled or
// imported rootfs upper, it also takes the journal file, which follows the
// filestore in c.goferFilestoreFDs. For a populated journaled rootfs upper
// (tar or filesystem restore), it returns a post-mount activation callback.
func (c *containerMounter) configureOverlayFilestore(conf *config.Config, dst string, filestore *os.File, hasTar bool, tmpfsOpts *tmpfs.FilesystemOpts) (func(context.Context, *vfs.Filesystem) error, error) {
	resourceID := checkpoint.ResourceID{ContainerName: c.containerName, Path: dst}
	var (
		jcfg        specutils.JournalingRootfsUpperConfig
		journalFile *os.File
	)
	if dst == "/" {
		var err error
		jcfg, err = specutils.JournalingRootfsUpper(c.spec, conf)
		if err != nil {
			filestore.Close()
			return nil, err
		}
		if jcfg.Enabled || jcfg.ImportPath != "" {
			if c.goferFilestoreFDs.empty() {
				filestore.Close()
				return nil, fmt.Errorf("no journal file for the journaling rootfs upper")
			}
			journalFile = c.goferFilestoreFDs.removeAsFD().ReleaseToFile("overlay-journal")
		}
	}

	populate := c.l.fsRestore != nil || hasTar
	if jcfg.ImportPath != "" {
		if populate {
			filestore.Close()
			journalFile.Close()
			return nil, fmt.Errorf("journaling rootfs upper import cannot be used with filesystem restore or rootfs upper tar")
		}
		mf, j, st, err := openImportedJournalingUpper(filestore, journalFile, conf, jcfg, resourceID)
		if err != nil {
			return nil, fmt.Errorf("failed to import journaling rootfs upper: %w", err)
		}
		tmpfsOpts.MemoryFile = mf
		tmpfsOpts.Journal = j
		tmpfsOpts.JournalState = st
		return nil, nil
	}
	if jcfg.Enabled && !populate {
		mf, j, err := createJournalingUpper(filestore, journalFile, conf, jcfg, resourceID)
		if err != nil {
			return nil, fmt.Errorf("failed to create journaling rootfs upper: %w", err)
		}
		tmpfsOpts.MemoryFile = mf
		tmpfsOpts.Journal = j
		return nil, nil
	}

	mf, loaded, err := createPrivateMemoryFile(filestore, resourceID, c.containerID, c.l.fsRestore, jcfg.Enabled)
	if err != nil {
		journalFile.Close()
		return nil, fmt.Errorf("failed to create memory file for overlay: %v", err)
	}
	sourceTar, err := c.l.fsRestore.tmpfsSourceTar(resourceID, c.containerID)
	if err != nil {
		mf.Destroy()
		journalFile.Close()
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
			l.activateJournalingUpperAsync(ctx, conf, cid, upper, imageID, journalFile, func() error { return fsr.wait(cid) })
			return nil
		}, nil
	}
	return func(ctx context.Context, upper *vfs.Filesystem) error {
		if err := l.activateJournalingUpper(ctx, conf, cid, upper, imageID, journalFile, false /* pause */); err != nil {
			return fmt.Errorf("failed to activate the journaling rootfs upper journal: %w", err)
		}
		return nil
	}, nil
}

// createJournalingUpper initializes a fresh MemoryFile on filestore and a
// fresh journal in journalFile. It takes ownership of filestore and
// journalFile.
func createJournalingUpper(filestore, journalFile *os.File, conf *config.Config, jcfg specutils.JournalingRootfsUpperConfig, resourceID checkpoint.ResourceID) (*pgalloc.MemoryFile, *journal.Journal, error) {
	mf, err := pgalloc.NewMemoryFile(filestore, journalingMemoryFileOpts(resourceID, false /* keepContents */))
	if err != nil {
		filestore.Close()
		journalFile.Close()
		return nil, nil, err
	}
	j, err := journal.Create(journalFile, journalingUpperOpts(conf, jcfg.ImageID))
	if err != nil {
		mf.Destroy()
		journalFile.Close()
		return nil, nil, err
	}
	log.Infof("Created journaling rootfs upper for %v", resourceID)
	return mf, j, nil
}

// openImportedJournalingUpper replays the imported journal in journalFile and
// adopts the filestore pages that it references into a new MemoryFile. If
// jcfg.Enabled is true, it also returns an open Journal to continue journaling
// into journalFile. It takes ownership of filestore and journalFile.
func openImportedJournalingUpper(filestore, journalFile *os.File, conf *config.Config, jcfg specutils.JournalingRootfsUpperConfig, resourceID checkpoint.ResourceID) (*pgalloc.MemoryFile, *journal.Journal, *journal.State, error) {
	mf, err := pgalloc.NewMemoryFile(filestore, journalingMemoryFileOpts(resourceID, true /* keepContents */))
	if err != nil {
		filestore.Close()
		journalFile.Close()
		return nil, nil, nil, err
	}
	j, st, err := journal.Open(mf, journalFile, journalingUpperOpts(conf, jcfg.ImageID), jcfg.Enabled)
	if err != nil || !jcfg.Enabled {
		journalFile.Close()
	}
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

// activateJournalingUpper creates a journal in journalFile and starts
// journaling on upper after a restore, filesystem restore, or tar archive
// populated it. It takes ownership of journalFile.
func (l *Loader) activateJournalingUpper(ctx context.Context, conf *config.Config, cid string, upper *vfs.Filesystem, imageID string, journalFile *os.File, pause bool) error {
	mf := tmpfs.MemoryFileOf(upper)
	if mf == nil {
		journalFile.Close()
		return fmt.Errorf("journaling rootfs upper is not a tmpfs filesystem")
	}
	if err := mf.AwaitLoadAll(); err != nil {
		journalFile.Close()
		return fmt.Errorf("failed to load journaling rootfs upper pages: %w", err)
	}
	if pause {
		l.k.Pause()
		defer l.k.Unpause()
	}
	j, err := journal.CreateIncomplete(journalFile, journalingUpperOpts(conf, imageID))
	if err != nil {
		journalFile.Close()
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

// syncSelfFilestoreWhiteout hides this sandbox's self-backed filestore (and,
// if journaled is true, its journal file) in upperFS without altering
// upperFS's root directory timestamps, and removes any imported self-filestore
// whiteouts from earlier sandboxes that do not exist on lowerRootVD.
func syncSelfFilestoreWhiteout(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, upperFS *vfs.Filesystem, lowerRootVD vfs.VirtualDentry, sandboxID string, journaled bool) error {
	selfNames := []string{sentryapi.SelfFilestoreName(sandboxID)}
	if journaled {
		selfNames = append(selfNames, sentryapi.SelfJournalName(sandboxID))
	}
	var remove []string
	if lowerRootVD.Ok() {
		for _, name := range tmpfs.SelfFilestoreWhiteouts(upperFS) {
			if slices.Contains(selfNames, name) {
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
	return tmpfs.SyncSelfFilestoreWhiteouts(ctx, upperFS, selfNames, remove)
}

type restoredJournalingUpper struct {
	conf    *config.Config
	cid     string
	upper   *vfs.Filesystem
	imageID string

	// journalFile is the journal file of upper, or nil after activation
	// took ownership of it.
	journalFile *os.File
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
			if t.journalFile != nil {
				t.journalFile.Close()
			}
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
	for i := range r.targets {
		t := &r.targets[i]
		journalFile := t.journalFile
		t.journalFile = nil
		if err := r.l.activateJournalingUpper(ctx, t.conf, t.cid, t.upper, t.imageID, journalFile, true /* pause */); err != nil {
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

		journalFile := l.takeRestoredJournalFile(cont.cid)
		if journalFile == nil {
			res.release(ctx)
			return nil, fmt.Errorf("container %q: no journal file for the journaling rootfs upper", cont.cid)
		}
		upperVD, err := l.containerRootUpperVD(ctx, cont.cid)
		if err != nil {
			journalFile.Close()
			res.release(ctx)
			return nil, err
		}
		upperFS := upperVD.Mount().Filesystem()
		if cont.goferMountConfs[0].IsSelfBacked() {
			creds := auth.NewRootCredentials(l.k.RootUserNamespace())
			if err := syncSelfFilestoreWhiteout(ctx, l.k.VFS(), creds, upperFS, vfs.VirtualDentry{}, l.sandboxID, true /* journaled */); err != nil {
				journalFile.Close()
				upperVD.DecRef(ctx)
				res.release(ctx)
				return nil, fmt.Errorf("container %q: failed to create self-filestore whiteout: %w", cont.cid, err)
			}
		}
		upperFS.IncRef()
		upperVD.DecRef(ctx)
		l.journalingUpperWG.Add(1)
		res.targets = append(res.targets, restoredJournalingUpper{
			conf:        cont.conf,
			cid:         cont.cid,
			upper:       upperFS,
			imageID:     jcfg.ImageID,
			journalFile: journalFile,
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
// kernel starts and waitFn returns. It takes ownership of journalFile.
func (l *Loader) activateJournalingUpperAsync(ctx context.Context, conf *config.Config, cid string, upper *vfs.Filesystem, imageID string, journalFile *os.File, waitFn func() error) {
	upper.IncRef()
	l.journalingUpperWG.Add(1)
	run := func(cancel bool) {
		defer l.journalingUpperWG.Done()
		defer upper.DecRef(ctx)
		if cancel {
			journalFile.Close()
			return
		}
		if err := waitFn(); err != nil {
			journalFile.Close()
			l.killForJournalingUpper(fmt.Errorf("container %q: populating the upper failed: %w", cid, err))
			return
		}
		if err := l.activateJournalingUpper(ctx, conf, cid, upper, imageID, journalFile, true /* pause */); err != nil {
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

// stashRestoredJournalFile saves the journal file of the journaling rootfs
// upper of container cid until its journal is activated after restore.
func (l *Loader) stashRestoredJournalFile(cid string, f *os.File) {
	l.journalingUpperMu.Lock()
	defer l.journalingUpperMu.Unlock()
	if l.restoredJournalFiles == nil {
		l.restoredJournalFiles = make(map[string]*os.File)
	}
	if old := l.restoredJournalFiles[cid]; old != nil {
		old.Close()
	}
	l.restoredJournalFiles[cid] = f
}

// takeRestoredJournalFile returns the journal file saved by
// stashRestoredJournalFile for container cid, or nil. The caller takes
// ownership of the file.
func (l *Loader) takeRestoredJournalFile(cid string) *os.File {
	l.journalingUpperMu.Lock()
	defer l.journalingUpperMu.Unlock()
	f := l.restoredJournalFiles[cid]
	delete(l.restoredJournalFiles, cid)
	return f
}
