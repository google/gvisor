// Copyright 2024 The gVisor Authors.
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

package proc

import (
	"bytes"
	goContext "context"
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

func (fs *filesystem) newGvisorInode(ctx context.Context, root *auth.Credentials, internalData *InternalData, k *kernel.Kernel) kernfs.Inode {
	gvisorFiles := make(map[string]kernfs.Inode)
	if internalData.GVisorMarkerFile {
		gvisorFiles["kernel_is_gvisor"] = fs.newInode(ctx, root, 0444, newStaticFile("gvisor\n"))
	}
	log.Infof("Setting up checkpoint files under [procfs]/gvisor")
	gvisorFiles["checkpoint"] = newCheckpointInode(ctx, k, root, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), internalData.SaveTriggerEnabled)
	gvisorFiles["spec_environ"] = fs.newInode(ctx, root, 0444, &specEnvironData{k: k})
	if internalData.FSCheckpointEnabled {
		log.Infof("Setting up fscheckpoint files under [procfs]/gvisor")
		gvisorFiles["fscheckpoint"] = newFSCheckpointInode(ctx, k, root, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno())
	}
	if len(gvisorFiles) == 0 {
		return nil
	}
	return fs.newStaticDir(ctx, root, gvisorFiles)
}

// checkpointInode represents the inode for /proc/gvisor/checkpoint.
//
// +stateify savable
type checkpointInode struct {
	// This uses fdInfoDirInodeRefs despite not being fdInfoDirInode. This is
	// because to prevent a hypothetical checkpointInodeRefs from leaking to
	// OSS, we would need Copybara to delete the relevant
	// go_template_instance() BUILD target, and while this is possible it seems
	// to require replicating the whole target in Copybara config to make the
	// deletion reversible. This only affects the reference leak warning that
	// is printed when reference leak detection is enabled. We pick
	// fdInfoDirInodeRefs since it's furthest from procfs root, and therefore
	// least likely to be affected by actual reference leaks (since children
	// may propagate reference leaks to their parents).
	kernfs.InodeAttrs
	kernfs.InodeNoStatFS
	fdInfoDirInodeRefs
	kernfs.InodeTemporary
	kernfs.InodeNotAnonymous
	kernfs.InodeNotDirectory
	kernfs.InodeNotSymlink
	kernfs.InodeWatches
	kernfs.InodeFSOwned
	locks vfs.FileLocks

	k                  *kernel.Kernel
	rdevMajor          uint32
	saveTriggerEnabled bool
}

var _ kernfs.Inode = (*checkpointInode)(nil)

func newCheckpointInode(ctx context.Context, k *kernel.Kernel, creds *auth.Credentials, devMajor, devMinor uint32, ino uint64, saveTriggerEnabled bool) *checkpointInode {
	rdevMajor, err := k.VFS().GetDynamicCharDevMajor()
	if err != nil {
		panic(fmt.Sprintf("failed to allocate device number for /proc/gvisor/checkpoint: %v", err))
	}
	perm := linux.FileMode(0444)
	if saveTriggerEnabled {
		perm = linux.FileMode(0666)
	}
	f := &checkpointInode{
		k:                  k,
		rdevMajor:          rdevMajor,
		saveTriggerEnabled: saveTriggerEnabled,
	}
	f.fdInfoDirInodeRefs.InitRefs()
	// Appear to be a character device so that applications don't carelessly
	// try to read from us.
	f.InodeAttrs.Init(ctx, creds, devMajor, devMinor, ino, linux.ModeCharacterDevice|perm)
	return f
}

// DecRef implements kernfs.Inode.DecRef.
func (f *checkpointInode) DecRef(ctx context.Context) {
	f.fdInfoDirInodeRefs.DecRef(func() {
		f.k.VFS().PutDynamicCharDevMajor(f.rdevMajor)
	})
}

// Stat implements kernfs.Inode.Stat.
func (f *checkpointInode) Stat(ctx context.Context, vfsfs *vfs.Filesystem, opts vfs.StatOptions) (linux.Statx, error) {
	stat, err := f.InodeAttrs.Stat(ctx, vfsfs, opts)
	stat.RdevMajor = f.rdevMajor
	stat.RdevMinor = 0
	return stat, err
}

// CheckPermissions implements Inode.CheckPermissions.
func (f *checkpointInode) CheckPermissions(ctx context.Context, creds *auth.Credentials, ats vfs.AccessTypes) error {
	if ats.MayWrite() && !f.saveTriggerEnabled {
		// Even though file mode is 0444, the root user can still open the file
		// for writing because it has CAP_DAC_OVERRIDE. Explicitly reject here.
		return linuxerr.EPERM
	}
	return f.InodeAttrs.CheckPermissions(ctx, creds, ats)
}

// Open implements kernfs.Inode.Open.
func (f *checkpointInode) Open(ctx context.Context, rp *vfs.ResolvingPath, d *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	data := &checkpointFD{
		k:              f.k,
		inode:          f,
		countToWaitFor: f.k.CheckpointGen().Count + 1,
	}
	data.initKey()

	data.vfsfd.Init(data, opts.Flags, rp.Credentials(), rp.Mount(), d.VFSDentry(), &vfs.FileDescriptionOptions{})
	return &data.vfsfd, nil
}

// checkpointFD implements vfs.FileDescription for /proc/gvisor/checkpoint.
//
// +stateify savable
type checkpointFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.NoLockFD

	k              *kernel.Kernel
	inode          kernfs.Inode
	countToWaitFor uint32
	waiters        waiter.Queue

	// This is the key used to unregister the checkpoint wait. It must be acquired again
	// after a restore.
	key any `state:"nosave"`

	mu     sync.Mutex `state:"nosave"`
	result string
	off    int64
}

var _ vfs.FileDescriptionImpl = (*checkpointFD)(nil)

func (fd *checkpointFD) initKey() {
	fd.key = fd.k.CheckpointWait.Register(fd.onRestoreOrResume, fd.countToWaitFor)
}

func (fd *checkpointFD) afterLoad(_ goContext.Context) {
	fd.initKey()
}

// Release implements vfs.FileDescription.Release. It stops waiting for the checkpoint.
func (fd *checkpointFD) Release(context.Context) {
	fd.k.CheckpointWait.Unregister(fd.key)
}

func (fd *checkpointFD) onRestoreOrResume(gen kernel.CheckpointGeneration, err error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()

	if len(fd.result) > 0 {
		// Result is already determined, nothing else to do.
		return
	}

	switch {
	case err != nil:
		fd.result = "error\n"
	case gen.Restore:
		// This could race if there is another checkpoint done before the caller can
		// read it. In the worst case, the caller may get "restore" more than once,
		// but it would be getting "restore" from one of the other FDs anyway.
		// Also, checkpoint is not called in quick succession.
		fd.result = "restore\n"
	default:
		fd.result = "resume\n"
	}

	fd.waiters.Notify(waiter.ReadableEvents)
}

// PRead implements vfs.FileDescription.PRead.
func (fd *checkpointFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, _ vfs.ReadOptions) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	return fd.preadLocked(ctx, dst, offset)
}

// PRead implements vfs.FileDescription.Read.
func (fd *checkpointFD) Read(ctx context.Context, dst usermem.IOSequence, _ vfs.ReadOptions) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()

	n, err := fd.preadLocked(ctx, dst, fd.off)
	fd.off += n
	return n, err
}

// preadLocked returns WouldBlock until the next checkpoint is done and returns the result. Which
// checkpoint to wait is determined when the FD is first opened. This allows the caller to first
// trigger the checkpoint asynchronously, by writing to the file, and then reading the result
// without racing. The read can also happen before writing to the checkpoint file. And writing isn't
// even required. This allows for independent processes to wait for the checkpoint to complete.
//
// After the checkpoint is completed, reading always returns the same result. To wait the next
// checkpoint, the file must be opened again.
//
// The result is one of:
// * "resume": the checkpoint has completed (or failed), and the workload is running again.
// * "restore": the cloned instance was restored and is running again.
// * "error": the checkpoint has failed. Note that the workload also resumes in this case.
func (fd *checkpointFD) preadLocked(ctx context.Context, dst usermem.IOSequence, offset int64) (int64, error) {
	if len(fd.result) == 0 {
		// If the result is empty, it means the checkpoint has not completed yet.
		return 0, linuxerr.ErrWouldBlock
	}

	if offset >= int64(len(fd.result)) {
		return 0, io.EOF
	}
	n, err := dst.CopyOut(ctx, []byte(fd.result[offset:]))
	return int64(n), err
}

// PWrite implements vfs.FileDescription.PWrite.
func (fd *checkpointFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return fd.write(ctx, src, offset)
}

// Write implements vfs.FileDescription.Write.
func (fd *checkpointFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	return fd.write(ctx, src, 0)
}

// write triggers a checkpoint when "1" is written.
func (fd *checkpointFD) write(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 || src.NumBytes() > 2 {
		return 0, linuxerr.EINVAL
	}
	if src.NumBytes() == 0 {
		return 0, nil
	}

	var buf [2]byte
	n, err := src.CopyIn(ctx, buf[:])
	if err != nil {
		return 0, err
	}
	// Accept new line at the end to allow `echo 1` for convenience.
	if in := string(buf[:n]); in != "1" && in != "1\n" {
		return 0, linuxerr.EINVAL
	}

	log.Infof("Checkpoint triggered by user")
	if err := fd.k.Saver().SaveAsync(); err != nil {
		return 0, err
	}
	return src.NumBytes(), nil
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *checkpointFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()

	switch whence {
	case linux.SEEK_SET:
		// Use offset as given.
	case linux.SEEK_CUR:
		offset += fd.off
	case linux.SEEK_END:
		offset += int64(len(fd.result))
	default:
		return 0, linuxerr.EINVAL
	}
	if offset < 0 {
		return 0, linuxerr.EINVAL
	}
	fd.off = offset
	return offset, nil
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *checkpointFD) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	fs := fd.vfsfd.VirtualDentry().Mount().Filesystem()
	return fd.inode.Stat(ctx, fs, opts)
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *checkpointFD) SetStat(context.Context, vfs.SetStatOptions) error {
	return linuxerr.EPERM
}

// Readiness implements vfs.FileDescriptionImpl.Readiness.
func (fd *checkpointFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	if (mask & waiter.ReadableEvents) != 0 {
		fd.mu.Lock()
		defer fd.mu.Unlock()

		if len(fd.result) > 0 {
			return waiter.ReadableEvents
		}
	}
	return 0
}

// EventRegister implements vfs.FileDescriptionImpl.EventRegister.
func (fd *checkpointFD) EventRegister(e *waiter.Entry) error {
	fd.waiters.EventRegister(e)
	return nil
}

// EventUnregister implements vfs.FileDescriptionImpl.EventUnregister.
func (fd *checkpointFD) EventUnregister(e *waiter.Entry) {
	fd.waiters.EventUnregister(e)
}

// specEnvironData implements vfs.DynamicBytesSource for /proc/gvisor/spec_environ.
//
// +stateify savable
type specEnvironData struct {
	dynamicBytesFileSetAttr

	k *kernel.Kernel
}

var _ dynamicInode = (*specEnvironData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (r *specEnvironData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	t := kernel.TaskFromContext(ctx)
	if t == nil {
		// The caller is not a task. Return an empty string.
		return nil
	}
	cid := t.ContainerID()
	cname := r.k.ContainerName(cid)
	if cname == "" {
		log.Warningf("Container name not found for container ID %q", cid)
		return nil
	}
	env := r.k.Saver().SpecEnviron(cname)
	for _, e := range env {
		buf.WriteString(e)
		buf.WriteByte(0)
	}
	return nil
}

// fsCheckpointInode implements kernfs.Inode for /proc/gvisor/fscheckpoint.
//
// +stateify savable
type fsCheckpointInode struct {
	// This uses fdInfoDirInodeRefs for the same reason as checkpointInode.
	kernfs.InodeAttrs
	kernfs.InodeNoStatFS
	fdInfoDirInodeRefs
	kernfs.InodeTemporary
	kernfs.InodeNotAnonymous
	kernfs.InodeNotDirectory
	kernfs.InodeNotSymlink
	kernfs.InodeWatches
	kernfs.InodeFSOwned
	locks vfs.FileLocks

	k         *kernel.Kernel
	rdevMajor uint32
}

func newFSCheckpointInode(ctx context.Context, k *kernel.Kernel, creds *auth.Credentials, devMajor, devMinor uint32, ino uint64) *fsCheckpointInode {
	rdevMajor, err := k.VFS().GetDynamicCharDevMajor()
	if err != nil {
		panic(fmt.Sprintf("failed to allocate device number for /proc/gvisor/fscheckpoint: %v", err))
	}
	i := &fsCheckpointInode{
		k:         k,
		rdevMajor: rdevMajor,
	}
	i.fdInfoDirInodeRefs.InitRefs()
	// Appear to be a character device so that applications don't carelessly
	// try to read from us.
	i.InodeAttrs.Init(ctx, creds, devMajor, devMinor, ino, linux.ModeCharacterDevice|0o666)
	return i
}

// DecRef implements kernfs.Inode.DecRef.
func (i *fsCheckpointInode) DecRef(ctx context.Context) {
	i.fdInfoDirInodeRefs.DecRef(func() {
		i.k.VFS().PutDynamicCharDevMajor(i.rdevMajor)
	})
}

// Stat implements kernfs.Inode.Stat.
func (i *fsCheckpointInode) Stat(ctx context.Context, vfsfs *vfs.Filesystem, opts vfs.StatOptions) (linux.Statx, error) {
	stat, err := i.InodeAttrs.Stat(ctx, vfsfs, opts)
	stat.RdevMajor = i.rdevMajor
	stat.RdevMinor = 0
	return stat, err
}

// Open implements kernfs.Inode.Open.
func (i *fsCheckpointInode) Open(ctx context.Context, rp *vfs.ResolvingPath, d *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	f := &fsCheckpointFile{
		k:     i.k,
		inode: i,
	}
	f.vfsfd.Init(f, opts.Flags, rp.Credentials(), rp.Mount(), d.VFSDentry(), &vfs.FileDescriptionOptions{
		DenyPWrite:        true,
		UseDentryMetadata: true,
	})
	return &f.vfsfd, nil
}

// fsCheckpointFile implements vfs.FileDescriptionImpl for
// /proc/gvisor/fscheckpoint.
//
// +stateify savable
type fsCheckpointFile struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	k     *kernel.Kernel
	inode *fsCheckpointInode

	state       atomicbitops.Uint32 `state:"nosave"` // monotonically increasing
	q           waiter.Queue
	result      string `state:"nosave"` // immutable once state becomes fsSaveFinished
	resultSaved string

	mu  sync.Mutex `state:"nosave"`
	off int64
}

// Possible values for fsCheckpointFile.state.
const (
	fsSaveUnstarted uint32 = iota
	fsSaveStarted
	fsSaveFinished
)

// Release implements vfs.FileDescription.Release.
func (f *fsCheckpointFile) Release(context.Context) {
	// no-op
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (f *fsCheckpointFile) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	if f.state.Load() != fsSaveFinished {
		return 0, linuxerr.ErrWouldBlock
	}
	if offset >= int64(len(f.result)) {
		return 0, io.EOF
	}
	n, err := dst.CopyOut(ctx, []byte(f.result[offset:]))
	return int64(n), err
}

// Read implements vfs.FileDescriptionImpl.Read.
func (f *fsCheckpointFile) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.PRead(ctx, dst, f.off, opts)
	f.off += n
	return n, err
}

// Write implements vfs.FileDescriptionImpl.Write.
func (f *fsCheckpointFile) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	if src.NumBytes() > 2 {
		return 0, linuxerr.EINVAL
	}
	if src.NumBytes() == 0 {
		return 0, nil
	}

	var buf [2]byte
	n, err := src.CopyIn(ctx, buf[:])
	if err != nil {
		return 0, err
	}
	// Accept new line at the end to allow `echo 1` for convenience.
	if in := string(buf[:n]); in != "1" && in != "1\n" {
		return 0, linuxerr.EINVAL
	}

	if f.state.Load() != fsSaveUnstarted || !f.state.CompareAndSwap(fsSaveUnstarted, fsSaveStarted) {
		return 0, linuxerr.EBUSY
	}
	saver := f.k.Saver()
	if saver == nil {
		f.result = "error\n"
		f.state.Store(fsSaveFinished)
		return 0, linuxerr.ENXIO // consistent with runsc/boot.Loader.SaveAsync
	}
	log.Infof("Filesystem checkpoint saving triggered by user")
	go func() {
		if err := saver.FSSave(); err != nil {
			log.Warningf("Filesystem checkpoint saving failed: %v", err)
			f.result = "error\n"
		} else {
			log.Infof("Filesystem checkpoint saving succeeded")
			f.result = "resume\n"
		}
		f.state.Store(fsSaveFinished)
		f.q.Notify(waiter.ReadableEvents)
	}()
	return int64(n), nil
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (f *fsCheckpointFile) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	if f.state.Load() != fsSaveFinished {
		return 0, linuxerr.ErrWouldBlock
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch whence {
	case linux.SEEK_SET:
		// Use offset as given.
	case linux.SEEK_CUR:
		offset += f.off
	case linux.SEEK_END:
		offset += int64(len(f.result))
	default:
		return 0, linuxerr.EINVAL
	}
	if offset < 0 {
		return 0, linuxerr.EINVAL
	}
	f.off = offset
	return offset, nil
}

// Readiness implements waiter.Waitable.Readiness.
func (f *fsCheckpointFile) Readiness(mask waiter.EventMask) waiter.EventMask {
	switch f.state.Load() {
	case fsSaveUnstarted:
		return waiter.WritableEvents
	case fsSaveFinished:
		return waiter.ReadableEvents
	default:
		return 0
	}
}

// EventRegister implements waiter.Waitable.EventRegister.
func (f *fsCheckpointFile) EventRegister(e *waiter.Entry) error {
	f.q.EventRegister(e)
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (f *fsCheckpointFile) EventUnregister(e *waiter.Entry) {
	f.q.EventUnregister(e)
}

// beforeSave is invoked by stateify.
func (f *fsCheckpointFile) beforeSave() {
	// Note that we can't wait for filesystem saving to complete, because it
	// may be blocked on Kernel.extMu, held by kernel saving; but we also can't
	// assume that f.state and f.result won't be mutated by filesystem saving,
	// since the filesystem saving goroutine may have already passed the
	// Kernel.extMu critical section.
	switch f.state.Load() {
	case fsSaveStarted:
		f.resultSaved = "unknown\n"
	case fsSaveFinished:
		f.resultSaved = f.result
	}
}

// afterLoad is invoked by stateify.
func (f *fsCheckpointFile) afterLoad(ctx goContext.Context) {
	if f.resultSaved != "" {
		f.result = f.resultSaved
		f.state.Store(fsSaveFinished)
		f.q.Notify(waiter.ReadableEvents)
	}
}
