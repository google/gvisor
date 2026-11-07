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

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/overlay"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs/journal"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
	"gvisor.dev/gvisor/runsc/version"
)

// This file implements the sentry side of the journaling rootfs upper. See
// config.Config.JournalingRootfsUpper and
// specutils.AnnotationRootfsUpperJournal. Each container can have one.
//
// Without an image to restore, a container's root overlay upper tmpfs is
// rebuilt from its journal (openJournalingUpper).
//
// An image (a checkpoint, a filesystem checkpoint, or a rootfs upper tar) can
// instead populate the upper with the standard code. runsc replaces the
// journal with a new one that is marked incomplete, so that a crash before
// the population completes makes the next start fail. After the population
// completes, activateJournalingUpperAfterPopulate starts a new journal from a
// snapshot of the upper, which clears the mark.

// journalingUpper is the journaling rootfs upper of a container.
type journalingUpper struct {
	// prefix is the path prefix of the upper's files. prefix is immutable.
	prefix string

	// imageID identifies the lower layer. imageID is immutable.
	imageID string

	// journal is the journal file, until the container's root overlay or
	// activateJournalingUpperAfterPopulate takes it.
	journal *os.File
}

// addJournalingUpper records journalFile as the journal of the journaling
// rootfs upper of container cid. It takes ownership of journalFile.
func (l *Loader) addJournalingUpper(cid string, spec *specs.Spec, conf *config.Config, journalFile *os.File) error {
	prefix, imageID, err := specutils.JournalingRootfsUpper(spec, conf)
	if err != nil {
		journalFile.Close()
		return err
	}
	if prefix == "" {
		journalFile.Close()
		return fmt.Errorf("container %q has a journal, but no journaling rootfs upper", cid)
	}
	l.journalingUpperMu.Lock()
	defer l.journalingUpperMu.Unlock()
	if l.journalingUppers == nil {
		l.journalingUppers = make(map[string]*journalingUpper)
	}
	if old, ok := l.journalingUppers[cid]; ok && old.journal != nil {
		old.journal.Close()
	}
	l.journalingUppers[cid] = &journalingUpper{prefix: prefix, imageID: imageID, journal: journalFile}
	return nil
}

// addJournalingUpperFromPayload records a dup of f, a file in a start or
// restore request payload, as the journal of the journaling rootfs upper of
// the container that args starts.
func (l *Loader) addJournalingUpperFromPayload(args *sentryapi.StartArgs, f *os.File) error {
	dup, err := unix.Dup(int(f.Fd()))
	if err != nil {
		return fmt.Errorf("error dup'ing journaling rootfs upper journal: %w", err)
	}
	return l.addJournalingUpper(args.CID, args.Spec, args.Conf, os.NewFile(uintptr(dup), "journaling-rootfs-upper-journal"))
}

// hasJournalingUpper returns true if container cid has a journaling rootfs
// upper.
func (l *Loader) hasJournalingUpper(cid string) bool {
	l.journalingUpperMu.Lock()
	defer l.journalingUpperMu.Unlock()
	_, ok := l.journalingUppers[cid]
	return ok
}

// takeJournalingUpperJournal returns the journaling rootfs upper of container
// cid and its journal file, or nil if there is none or the file was already
// taken. The caller owns the returned file.
func (l *Loader) takeJournalingUpperJournal(cid string) (*journalingUpper, *os.File) {
	l.journalingUpperMu.Lock()
	defer l.journalingUpperMu.Unlock()
	ju, ok := l.journalingUppers[cid]
	if !ok || ju.journal == nil {
		return nil, nil
	}
	f := ju.journal
	ju.journal = nil
	return ju, f
}

// closeJournalingUpperJournals closes the journal files that weren't taken.
// If cid isn't empty, it only closes container cid's.
func (l *Loader) closeJournalingUpperJournals(cid string) {
	l.journalingUpperMu.Lock()
	defer l.journalingUpperMu.Unlock()
	for id, ju := range l.journalingUppers {
		if (cid == "" || id == cid) && ju.journal != nil {
			_ = ju.journal.Close()
			ju.journal = nil
		}
	}
}

// checkJournalingUpperPopulate returns an error if an image can't populate
// the journaling rootfs upper of container cid. runsc creates a new journal
// marked incomplete when it creates a container from an image; a container
// that was created without an image uses its existing journal, which an image
// must not overwrite.
func (l *Loader) checkJournalingUpperPopulate(cid string) error {
	l.journalingUpperMu.Lock()
	defer l.journalingUpperMu.Unlock()
	ju, ok := l.journalingUppers[cid]
	if !ok {
		return nil
	}
	if ju.journal == nil {
		return fmt.Errorf("journaling rootfs upper journal at %s.journal is already in use", ju.prefix)
	}
	incomplete, err := journal.Incomplete(ju.journal)
	if err != nil {
		return err
	}
	if !incomplete {
		return fmt.Errorf("journaling rootfs upper: can't restore into a container that was created without an image, which uses the journal at %s.journal; create the container from the image instead, which replaces the journal", ju.prefix)
	}
	return nil
}

func (l *Loader) journalingUpperJournalOpts(ju *journalingUpper) journal.Options {
	return journal.Options{
		BuildID:    version.Version(),
		ImageID:    ju.imageID,
		RegionSize: l.journalingUpperRegionSize,
	}
}

// openJournalingUpper opens the filestore of ju, the journaling rootfs upper
// of a container, and journalFile, its journal. It returns the MemoryFile,
// which has adopted the pages that the journal refers to, and the journal and
// its state. It takes ownership of filestore and journalFile.
func (l *Loader) openJournalingUpper(ju *journalingUpper, filestore, journalFile *os.File, resourceID checkpoint.ResourceID) (*pgalloc.MemoryFile, *journal.Journal, *journal.State, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(filestore.Fd()), &stat); err != nil {
		filestore.Close()
		journalFile.Close()
		return nil, nil, nil, fmt.Errorf("failed to stat filestore: %w", err)
	}
	mf, err := pgalloc.NewMemoryFile(filestore, journalingMemoryFileOpts(resourceID, true /* keepContents */))
	if err != nil {
		filestore.Close()
		journalFile.Close()
		return nil, nil, nil, err
	}
	opts := l.journalingUpperJournalOpts(ju)
	opts.FilestoreSize = uint64(stat.Size)
	j, st, err := journal.Open(journalFile, opts)
	if err != nil {
		mf.Destroy()
		journalFile.Close()
		if errors.Is(err, journal.ErrIncomplete) {
			return nil, nil, nil, fmt.Errorf("journal at %s.journal is incomplete: a restore did not finish; restore again", ju.prefix)
		}
		return nil, nil, nil, err
	}
	if err := mf.AdoptExisting(st.UsedRanges(), usage.Tmpfs); err != nil {
		j.Close()
		mf.Destroy()
		return nil, nil, nil, fmt.Errorf("failed to adopt filestore pages: %w", err)
	}
	if st.Empty() {
		log.Infof("Created journaling rootfs upper %q", ju.prefix)
	} else {
		log.Infof("Opened journaling rootfs upper %q with %d inodes and %d filestore ranges", ju.prefix, len(st.Inodes), len(st.UsedRanges()))
	}
	return mf, j, st, nil
}

// journalingMemoryFileOpts returns the options of the MemoryFile of the
// journaling rootfs upper. They match createPrivateMemoryFile, except that
// the filestore must outlive the sandbox, so it is never decommitted on
// destruction.
func journalingMemoryFileOpts(resourceID checkpoint.ResourceID, keepContents bool) pgalloc.MemoryFileOpts {
	return pgalloc.MemoryFileOpts{
		DiskBackedFile:          true,
		KeepFileContents:        keepContents,
		DisableMemoryAccounting: true,
		DisableIMAWorkAround:    true,
		ResourceID:              resourceID,
	}
}

// activateJournalingUpperAfterPopulate starts a new journal for upper, the
// journaling rootfs upper of container cid, after an image populated it. It
// waits for page loading into upper's MemoryFile to complete, then snapshots
// upper into the new journal. If pause is true, the kernel is paused during
// the snapshot; pause may only be false if no task can use upper yet.
//
// On failure, the journal stays marked incomplete, so the next start of the
// container fails. The caller must then stop the sandbox, because changes to
// upper are not journaled.
func (l *Loader) activateJournalingUpperAfterPopulate(cid string, upper *vfs.Filesystem, pause bool) error {
	ju, journalFile := l.takeJournalingUpperJournal(cid)
	if journalFile == nil {
		return fmt.Errorf("journaling rootfs upper journal of container %q is missing or already in use", cid)
	}
	if l.journalingUpperFailActivation {
		journalFile.Close()
		return fmt.Errorf("activation failure injected by --TESTONLY-journaling-rootfs-upper-fault")
	}
	mf := tmpfs.MemoryFileOf(upper)
	if mf == nil {
		journalFile.Close()
		return fmt.Errorf("journaling rootfs upper is not a tmpfs filesystem")
	}
	if err := mf.AwaitLoadAll(); err != nil {
		journalFile.Close()
		return fmt.Errorf("failed to load journaling rootfs upper pages: %w", err)
	}
	j, err := journal.Reinit(journalFile, l.journalingUpperJournalOpts(ju))
	if err != nil {
		journalFile.Close()
		return err
	}
	if pause {
		// Pause the kernel, so that no system call is in progress while
		// the journal starts.
		l.k.Pause()
		defer l.k.Unpause()
	}
	if err := tmpfs.ActivateJournal(upper, j); err != nil {
		return err
	}
	log.Infof("Activated the journaling rootfs upper journal at %s.journal", ju.prefix)
	return nil
}

// activateJournalingUppersAfterRestore calls
// activateJournalingUpperAfterPopulate for the root overlay's upper layer of
// each container with a journaling rootfs upper, after a checkpoint restore.
func (l *Loader) activateJournalingUppersAfterRestore(ctx context.Context) error {
	l.journalingUpperMu.Lock()
	var cids []string
	for cid, ju := range l.journalingUppers {
		if ju.journal != nil {
			cids = append(cids, cid)
		}
	}
	l.journalingUpperMu.Unlock()
	for _, cid := range cids {
		upper, err := l.containerRootUpper(ctx, cid)
		if err != nil {
			return err
		}
		err = l.activateJournalingUpperAfterPopulate(cid, upper, true /* pause */)
		upper.DecRef(ctx)
		if err != nil {
			return fmt.Errorf("container %q: %w", cid, err)
		}
	}
	return nil
}

// containerRootUpper returns the upper layer of the root overlay of container
// cid, with a reference.
func (l *Loader) containerRootUpper(ctx context.Context, cid string) (*vfs.Filesystem, error) {
	l.mu.Lock()
	ep := l.processes[execID{cid: cid}]
	var tg *kernel.ThreadGroup
	if ep != nil {
		tg = ep.tg
	}
	l.mu.Unlock()
	if tg == nil {
		return nil, fmt.Errorf("container %q has no init process", cid)
	}
	mntns := tg.Leader().GetMountNamespace()
	if mntns == nil {
		return nil, fmt.Errorf("container %q has no mount namespace", cid)
	}
	defer mntns.DecRef(ctx)
	root := mntns.Root(ctx)
	defer root.DecRef(ctx)
	upper := overlay.UpperFilesystem(root.Mount().Filesystem())
	if upper == nil {
		return nil, fmt.Errorf("rootfs of container %q is not an overlay with an upper layer", cid)
	}
	upper.IncRef()
	return upper, nil
}

// activateJournalingUpperAsync arranges for
// activateJournalingUpperAfterPopulate to run for upper, the journaling
// rootfs upper of container cid, after the kernel starts and waitFn returns.
// If waitFn or the activation fails, the sandbox is killed. The activation
// waits for the kernel to start, so that killing the sandbox stops the
// container instead of failing its creation.
func (l *Loader) activateJournalingUpperAsync(ctx context.Context, cid string, upper *vfs.Filesystem, waitFn func() error) {
	upper.IncRef()
	fn := func() {
		defer upper.DecRef(ctx)
		if err := waitFn(); err != nil {
			l.killForJournalingUpper(fmt.Errorf("container %q: populating the upper failed: %w", cid, err))
			return
		}
		if err := l.activateJournalingUpperAfterPopulate(cid, upper, true /* pause */); err != nil {
			l.killForJournalingUpper(fmt.Errorf("container %q: %w", cid, err))
		}
	}
	l.journalingUpperMu.Lock()
	defer l.journalingUpperMu.Unlock()
	if l.journalingUpperKernelStarted {
		go fn()
		return
	}
	l.journalingUpperActivations = append(l.journalingUpperActivations, fn)
}

// startJournalingUpperActivations starts the activations that
// activateJournalingUpperAsync arranged before the kernel started, each in a
// new goroutine. Later activations start at once.
func (l *Loader) startJournalingUpperActivations() {
	l.journalingUpperMu.Lock()
	fns := l.journalingUpperActivations
	l.journalingUpperActivations = nil
	l.journalingUpperKernelStarted = true
	l.journalingUpperMu.Unlock()
	for _, fn := range fns {
		go fn()
	}
}

// killForJournalingUpper kills the sandbox because a journaling rootfs upper
// journal could not be activated, so that no change to the upper is lost
// silently. The journal stays marked incomplete, so the container can't start
// from it.
func (l *Loader) killForJournalingUpper(err error) {
	log.Warningf("Killing the sandbox: failed to activate a journaling rootfs upper journal: %v. The journal stays incomplete; restore again.", err)
	l.k.Kill(linux.WaitStatusTerminationSignal(linux.SIGKILL))
	l.stopIfKilled()
}
