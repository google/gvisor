// Copyright 2019 The gVisor Authors.
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

package vfs

import (
	"fmt"
	"runtime"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sync"
)

func TestMountTableLookupEmpty(t *testing.T) {
	var mt mountTable
	mt.Init()

	parent := &Mount{}
	point := &Dentry{}
	if m := mt.Lookup(parent, point); m != nil {
		t.Errorf("Empty mountTable lookup: got %p, wanted nil", m)
	}
}

func TestMountTableInsertLookup(t *testing.T) {
	var mt mountTable
	mt.Init()

	mount := &Mount{}
	mount.setKey(VirtualDentry{&Mount{}, &Dentry{}})
	mt.Insert(mount)

	if m := mt.Lookup(mount.parent(), mount.point()); m != mount {
		t.Errorf("mountTable positive lookup: got %p, wanted %p", m, mount)
	}

	otherParent := &Mount{}
	if m := mt.Lookup(otherParent, mount.point()); m != nil {
		t.Errorf("mountTable lookup with wrong mount parent: got %p, wanted nil", m)
	}
	otherPoint := &Dentry{}
	if m := mt.Lookup(mount.parent(), otherPoint); m != nil {
		t.Errorf("mountTable lookup with wrong mount point: got %p, wanted nil", m)
	}
}

// mountTestFilesystemType is a FilesystemType for filesystems that only exist
// to be mounted by tests.
type mountTestFilesystemType struct{}

// GetFilesystem implements FilesystemType.GetFilesystem.
func (fstype mountTestFilesystemType) GetFilesystem(ctx context.Context, vfsObj *VirtualFilesystem, creds *auth.Credentials, source string, opts GetFilesystemOptions) (*Filesystem, *Dentry, error) {
	fs := &mountTestFilesystem{}
	fs.vfsfs.Init(vfsObj, fstype, fs)
	return &fs.vfsfs, newMountTestDentry().dentry(), nil
}

// Name implements FilesystemType.Name.
func (mountTestFilesystemType) Name() string {
	return "mounttest"
}

// Release implements FilesystemType.Release.
func (mountTestFilesystemType) Release(ctx context.Context) {}

// mountTestFilesystem implements the parts of FilesystemImpl that mounting and
// unmounting need. All other methods panic if called.
type mountTestFilesystem struct {
	FilesystemImpl

	vfsfs Filesystem
}

// GetDentryAt implements FilesystemImpl.GetDentryAt.
func (*mountTestFilesystem) GetDentryAt(ctx context.Context, rp *ResolvingPath, opts GetDentryOptions) (*Dentry, error) {
	if !rp.Done() {
		// mountTestFilesystem has no directory structure, so only the dentry
		// that path resolution starts at can be resolved.
		return nil, linuxerr.ENOENT
	}
	d := rp.Start()
	d.IncRef()
	return d, nil
}

// Release implements FilesystemImpl.Release.
func (*mountTestFilesystem) Release(ctx context.Context) {}

// mountTestDentry is a Dentry that does nothing except count references, so
// that tests can check the references that VFS holds on it.
type mountTestDentry struct {
	vfsd    Dentry
	watches Watches

	refs atomicbitops.Int64
}

func newMountTestDentry() *mountTestDentry {
	d := &mountTestDentry{refs: atomicbitops.FromInt64(1)}
	d.vfsd.Init(d)
	return d
}

func (d *mountTestDentry) dentry() *Dentry {
	return &d.vfsd
}

// IncRef implements DentryImpl.IncRef.
func (d *mountTestDentry) IncRef() {
	d.refs.Add(1)
}

// TryIncRef implements DentryImpl.TryIncRef.
func (d *mountTestDentry) TryIncRef() bool {
	for {
		r := d.refs.Load()
		if r <= 0 {
			return false
		}
		if d.refs.CompareAndSwap(r, r+1) {
			return true
		}
	}
}

// DecRef implements DentryImpl.DecRef.
func (d *mountTestDentry) DecRef(ctx context.Context) {
	d.refs.Add(-1)
}

// InotifyWithParent implements DentryImpl.InotifyWithParent.
func (d *mountTestDentry) InotifyWithParent(ctx context.Context, events, cookie uint32, et EventType) {
}

// Watches implements DentryImpl.Watches.
func (d *mountTestDentry) Watches() *Watches {
	return &d.watches
}

// OnZeroWatches implements DentryImpl.OnZeroWatches.
func (d *mountTestDentry) OnZeroWatches(context.Context) {}

// mountTestSystem is a VirtualFilesystem with a single mount namespace whose
// root mount is a mountTestFilesystem.
type mountTestSystem struct {
	t     *testing.T
	ctx   context.Context
	creds *auth.Credentials
	vfs   *VirtualFilesystem
	mntns *MountNamespace
	root  VirtualDentry
}

func newMountTestSystem(t *testing.T) *mountTestSystem {
	t.Helper()
	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)
	vfsObj := &VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VFS init: %v", err)
	}
	vfsObj.MustRegisterFilesystemType("mounttest", mountTestFilesystemType{}, &RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "" /* source */, "mounttest", &MountOptions{}, nil /* nsfs */)
	if err != nil {
		t.Fatalf("failed to create mount namespace: %v", err)
	}
	ctx = WithMountNamespace(ctx, mntns)
	return &mountTestSystem{
		t:     t,
		ctx:   ctx,
		creds: creds,
		vfs:   vfsObj,
		mntns: mntns,
		root:  mntns.Root(ctx),
	}
}

func (s *mountTestSystem) destroy() {
	s.root.DecRef(s.ctx)
	s.mntns.DecRef(s.ctx)
}

// popAt returns a PathOperation that resolves to (mnt, d) without walking any
// path components.
func (s *mountTestSystem) popAt(mnt *Mount, d *mountTestDentry) *PathOperation {
	return &PathOperation{
		Root:  s.root,
		Start: MakeVirtualDentry(mnt, d.dentry()),
		Path:  fspath.Parse(""),
	}
}

// mount mounts a new mountTestFilesystem at (mnt, mp).
func (s *mountTestSystem) mount(mnt *Mount, mp *mountTestDentry, locked bool) *Mount {
	s.t.Helper()
	newMnt, err := s.vfs.MountAt(s.ctx, s.creds, "" /* source */, s.popAt(mnt, mp), "mounttest", &MountOptions{Locked: locked})
	if err != nil {
		s.t.Fatalf("MountAt() failed: %v", err)
	}
	return newMnt
}

// lazyUmount umounts the mount at (mnt, mp) with MNT_DETACH.
func (s *mountTestSystem) lazyUmount(mnt *Mount, mp *mountTestDentry) {
	s.t.Helper()
	if err := s.vfs.UmountAt(s.ctx, s.creds, s.popAt(mnt, mp), &UmountOptions{Flags: linux.MNT_DETACH}); err != nil {
		s.t.Fatalf("UmountAt() failed: %v", err)
	}
}

// mountState returns whether mnt is marked as umounted and its mount parent.
func (s *mountTestSystem) mountState(mnt *Mount) (bool, *Mount) {
	s.vfs.lockMounts()
	defer s.vfs.unlockMounts(s.ctx)
	return mnt.umounted, mnt.parent()
}

// TestPartlyUmountedMountKeepsMountpointRef tests that VFS holds a reference
// on a mount point for as long as a mount is connected to it, even after that
// mount has been marked as umounted.
//
// The mount is disconnected here by the destruction of its parent in Mount.destroy().
func TestPartlyUmountedMountKeepsMountpointRef(t *testing.T) {
	s := newMountTestSystem(t)
	defer s.destroy()

	// Mount a filesystem at pmp, a dentry in the root mount, and a locked
	// filesystem at mp, a dentry in the first one.
	pmp := newMountTestDentry()
	parent := s.mount(s.root.Mount(), pmp, false /* locked */)
	mp := newMountTestDentry()
	wantRefs := mp.refs.Load() + 1
	mnt := s.mount(parent, mp, true /* locked */)
	if got := mp.refs.Load(); got != wantRefs {
		t.Fatalf("mount point has %d references after being mounted on, want %d", got, wantRefs)
	}

	// Hold a reference on the parent mount, simulating an open file on the mount.
	// Otherwise the parent would be destroyed by the umount below.
	parent.IncRef()

	// mnt is locked, so umounting its parent leaves it marked as umounted but
	// still connected, until the parent is destroyed.
	s.lazyUmount(s.root.Mount(), pmp)

	umounted, mntParent := s.mountState(mnt)
	if !umounted {
		t.Errorf("mount was not marked as umounted")
	}
	if mntParent != parent {
		t.Fatalf("mount was disconnected from its parent; test no longer exercises the intended path")
	}
	if got := mp.refs.Load(); got != wantRefs {
		t.Errorf("mount point has %d references while a mount is connected to it, want %d", got, wantRefs)
	}

	// Dropping the last reference on the parent mount destroys it, which
	// disconnects mnt and releases the mount point reference, exactly once.
	parent.DecRef(s.ctx)
	if _, mntParent := s.mountState(mnt); mntParent != nil {
		t.Errorf("mount is still connected after its parent was destroyed")
	}
	if got, want := mp.refs.Load(), wantRefs-1; got != want {
		t.Errorf("mount point has %d references after the mount was disconnected, want %d", got, want)
	}
}

// TestForgetDeadMountpointReleasesMountpointRef is like
// TestPartlyUmountedMountKeepsMountpointRef, except that the mount is
// disconnected by the invalidation of its mount point, i.e. by
// VFS.forgetDeadMountpoint().
func TestForgetDeadMountpointReleasesMountpointRef(t *testing.T) {
	s := newMountTestSystem(t)
	defer s.destroy()

	pmp := newMountTestDentry()
	parent := s.mount(s.root.Mount(), pmp, false /* locked */)
	mp := newMountTestDentry()
	wantRefs := mp.refs.Load() + 1
	mnt := s.mount(parent, mp, true /* locked */)
	if got := mp.refs.Load(); got != wantRefs {
		t.Fatalf("mount point has %d references after being mounted on, want %d", got, wantRefs)
	}

	parent.IncRef()
	defer parent.DecRef(s.ctx)
	s.lazyUmount(s.root.Mount(), pmp)

	if _, mntParent := s.mountState(mnt); mntParent != parent {
		t.Fatalf("mount was disconnected from its parent; test no longer exercises the intended path")
	}
	if got := mp.refs.Load(); got != wantRefs {
		t.Errorf("mount point has %d references while a mount is connected to it, want %d", got, wantRefs)
	}

	// A filesystem invalidating the mount point disconnects mnt
	// and releases the mount point reference exactly once.
	for _, rc := range s.vfs.InvalidateDentry(s.ctx, mp.dentry()) {
		rc.DecRef(s.ctx)
	}
	if _, mntParent := s.mountState(mnt); mntParent != nil {
		t.Errorf("mount is still connected after its mount point was invalidated")
	}
	if got, want := mp.refs.Load(), wantRefs-1; got != want {
		t.Errorf("mount point has %d references after the mount was disconnected, want %d", got, want)
	}
}

// TODO(gvisor.dev/issue/1035): concurrent lookup/insertion/removal.

// must be powers of 2
var benchNumMounts = []int{1 << 2, 1 << 5, 1 << 8}

// For all of the following:
//
//   - BenchmarkMountTableFoo tests usage pattern "Foo" for mountTable.
//
//   - BenchmarkMountMapFoo tests usage pattern "Foo" for a
//
// sync.RWMutex-protected map. (Mutator benchmarks do not use a RWMutex, since
// mountTable also requires external synchronization between mutators.)
//
//   - BenchmarkMountSyncMapFoo tests usage pattern "Foo" for a sync.Map.
//
// ParallelLookup is by far the most common and performance-sensitive operation
// for this application. NegativeLookup is also important, but less so (only
// relevant with multiple mount namespaces and significant differences in
// mounts between them). Insertion and removal are benchmarked for
// completeness.
const enableComparativeBenchmarks = false

func newBenchMount() *Mount {
	mount := &Mount{}
	mount.setKey(VirtualDentry{&Mount{}, &Dentry{}})
	return mount
}

func BenchmarkMountTableParallelLookup(b *testing.B) {
	for numG, maxG := 1, runtime.GOMAXPROCS(0); numG >= 0 && numG <= maxG; numG *= 2 {
		for _, numMounts := range benchNumMounts {
			desc := fmt.Sprintf("%dx%d", numG, numMounts)
			b.Run(desc, func(b *testing.B) {
				var mt mountTable
				mt.Init()
				keys := make([]VirtualDentry, 0, numMounts)
				for i := 0; i < numMounts; i++ {
					mount := newBenchMount()
					mt.Insert(mount)
					keys = append(keys, mount.saveKey())
				}

				var ready sync.WaitGroup
				begin := make(chan struct{})
				var end sync.WaitGroup
				for g := 0; g < numG; g++ {
					ready.Add(1)
					end.Add(1)
					go func() {
						defer end.Done()
						ready.Done()
						<-begin
						for i := 0; i < b.N; i++ {
							k := keys[i&(numMounts-1)]
							m := mt.Lookup(k.mount, k.dentry)
							if m == nil {
								b.Errorf("Lookup failed")
								return
							}
							if parent := m.parent(); parent != k.mount {
								b.Errorf("Lookup returned mount with parent %p, wanted %p", parent, k.mount)
								return
							}
							if point := m.point(); point != k.dentry {
								b.Errorf("Lookup returned mount with point %p, wanted %p", point, k.dentry)
								return
							}
						}
					}()
				}

				ready.Wait()
				b.ResetTimer()
				close(begin)
				end.Wait()
			})
		}
	}
}

func BenchmarkMountMapParallelLookup(b *testing.B) {
	if !enableComparativeBenchmarks {
		b.Skipf("comparative benchmarks are disabled")
	}

	for numG, maxG := 1, runtime.GOMAXPROCS(0); numG >= 0 && numG <= maxG; numG *= 2 {
		for _, numMounts := range benchNumMounts {
			desc := fmt.Sprintf("%dx%d", numG, numMounts)
			b.Run(desc, func(b *testing.B) {
				var mu sync.RWMutex
				ms := make(map[VirtualDentry]*Mount)
				keys := make([]VirtualDentry, 0, numMounts)
				for i := 0; i < numMounts; i++ {
					mount := newBenchMount()
					key := mount.saveKey()
					ms[key] = mount
					keys = append(keys, key)
				}

				var ready sync.WaitGroup
				begin := make(chan struct{})
				var end sync.WaitGroup
				for g := 0; g < numG; g++ {
					ready.Add(1)
					end.Add(1)
					go func() {
						defer end.Done()
						ready.Done()
						<-begin
						for i := 0; i < b.N; i++ {
							k := keys[i&(numMounts-1)]
							mu.RLock()
							m := ms[k]
							mu.RUnlock()
							if m == nil {
								b.Errorf("Lookup failed")
								return
							}
							if parent := m.parent(); parent != k.mount {
								b.Errorf("Lookup returned mount with parent %p, wanted %p", parent, k.mount)
								return
							}
							if point := m.point(); point != k.dentry {
								b.Errorf("Lookup returned mount with point %p, wanted %p", point, k.dentry)
								return
							}
						}
					}()
				}

				ready.Wait()
				b.ResetTimer()
				close(begin)
				end.Wait()
			})
		}
	}
}

func BenchmarkMountSyncMapParallelLookup(b *testing.B) {
	if !enableComparativeBenchmarks {
		b.Skipf("comparative benchmarks are disabled")
	}

	for numG, maxG := 1, runtime.GOMAXPROCS(0); numG >= 0 && numG <= maxG; numG *= 2 {
		for _, numMounts := range benchNumMounts {
			desc := fmt.Sprintf("%dx%d", numG, numMounts)
			b.Run(desc, func(b *testing.B) {
				var ms sync.Map
				keys := make([]VirtualDentry, 0, numMounts)
				for i := 0; i < numMounts; i++ {
					mount := newBenchMount()
					key := mount.getKey()
					ms.Store(key, mount)
					keys = append(keys, key)
				}

				var ready sync.WaitGroup
				begin := make(chan struct{})
				var end sync.WaitGroup
				for g := 0; g < numG; g++ {
					ready.Add(1)
					end.Add(1)
					go func() {
						defer end.Done()
						ready.Done()
						<-begin
						for i := 0; i < b.N; i++ {
							k := keys[i&(numMounts-1)]
							mi, ok := ms.Load(k)
							if !ok {
								b.Errorf("Lookup failed")
								return
							}
							m := mi.(*Mount)
							if parent := m.parent(); parent != k.mount {
								b.Errorf("Lookup returned mount with parent %p, wanted %p", parent, k.mount)
								return
							}
							if point := m.point(); point != k.dentry {
								b.Errorf("Lookup returned mount with point %p, wanted %p", point, k.dentry)
								return
							}
						}
					}()
				}

				ready.Wait()
				b.ResetTimer()
				close(begin)
				end.Wait()
			})
		}
	}
}

func BenchmarkMountTableNegativeLookup(b *testing.B) {
	for _, numMounts := range benchNumMounts {
		desc := fmt.Sprintf("%d", numMounts)
		b.Run(desc, func(b *testing.B) {
			var mt mountTable
			mt.Init()
			for i := 0; i < numMounts; i++ {
				mt.Insert(newBenchMount())
			}
			negkeys := make([]VirtualDentry, 0, numMounts)
			for i := 0; i < numMounts; i++ {
				negkeys = append(negkeys, VirtualDentry{
					mount:  &Mount{},
					dentry: &Dentry{},
				})
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				k := negkeys[i&(numMounts-1)]
				m := mt.Lookup(k.mount, k.dentry)
				if m != nil {
					b.Fatalf("Lookup got %p, wanted nil", m)
				}
			}
		})
	}
}

func BenchmarkMountMapNegativeLookup(b *testing.B) {
	if !enableComparativeBenchmarks {
		b.Skipf("comparative benchmarks are disabled")
	}

	for _, numMounts := range benchNumMounts {
		desc := fmt.Sprintf("%d", numMounts)
		b.Run(desc, func(b *testing.B) {
			var mu sync.RWMutex
			ms := make(map[VirtualDentry]*Mount)
			for i := 0; i < numMounts; i++ {
				mount := newBenchMount()
				ms[mount.getKey()] = mount
			}
			negkeys := make([]VirtualDentry, 0, numMounts)
			for i := 0; i < numMounts; i++ {
				negkeys = append(negkeys, VirtualDentry{
					mount:  &Mount{},
					dentry: &Dentry{},
				})
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				k := negkeys[i&(numMounts-1)]
				mu.RLock()
				m := ms[k]
				mu.RUnlock()
				if m != nil {
					b.Fatalf("Lookup got %p, wanted nil", m)
				}
			}
		})
	}
}

func BenchmarkMountSyncMapNegativeLookup(b *testing.B) {
	if !enableComparativeBenchmarks {
		b.Skipf("comparative benchmarks are disabled")
	}

	for _, numMounts := range benchNumMounts {
		desc := fmt.Sprintf("%d", numMounts)
		b.Run(desc, func(b *testing.B) {
			var ms sync.Map
			for i := 0; i < numMounts; i++ {
				mount := newBenchMount()
				ms.Store(mount.saveKey(), mount)
			}
			negkeys := make([]VirtualDentry, 0, numMounts)
			for i := 0; i < numMounts; i++ {
				negkeys = append(negkeys, VirtualDentry{
					mount:  &Mount{},
					dentry: &Dentry{},
				})
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				k := negkeys[i&(numMounts-1)]
				m, _ := ms.Load(k)
				if m != nil {
					b.Fatalf("Lookup got %p, wanted nil", m)
				}
			}
		})
	}
}

func BenchmarkMountTableInsert(b *testing.B) {
	// Preallocate Mounts so that allocation time isn't included in the
	// benchmark.
	mounts := make([]*Mount, 0, b.N)
	for i := 0; i < b.N; i++ {
		mounts = append(mounts, newBenchMount())
	}

	var mt mountTable
	mt.Init()
	b.ResetTimer()
	for i := range mounts {
		mt.Insert(mounts[i])
	}
}

func BenchmarkMountMapInsert(b *testing.B) {
	if !enableComparativeBenchmarks {
		b.Skipf("comparative benchmarks are disabled")
	}

	// Preallocate Mounts so that allocation time isn't included in the
	// benchmark.
	mounts := make([]*Mount, 0, b.N)
	for i := 0; i < b.N; i++ {
		mounts = append(mounts, newBenchMount())
	}

	ms := make(map[VirtualDentry]*Mount)
	b.ResetTimer()
	for i := range mounts {
		mount := mounts[i]
		ms[mount.saveKey()] = mount
	}
}

func BenchmarkMountSyncMapInsert(b *testing.B) {
	if !enableComparativeBenchmarks {
		b.Skipf("comparative benchmarks are disabled")
	}

	// Preallocate Mounts so that allocation time isn't included in the
	// benchmark.
	mounts := make([]*Mount, 0, b.N)
	for i := 0; i < b.N; i++ {
		mounts = append(mounts, newBenchMount())
	}

	var ms sync.Map
	b.ResetTimer()
	for i := range mounts {
		mount := mounts[i]
		ms.Store(mount.saveKey(), mount)
	}
}

func BenchmarkMountTableRemove(b *testing.B) {
	mounts := make([]*Mount, 0, b.N)
	for i := 0; i < b.N; i++ {
		mounts = append(mounts, newBenchMount())
	}
	var mt mountTable
	mt.Init()
	for i := range mounts {
		mt.Insert(mounts[i])
	}

	b.ResetTimer()
	for i := range mounts {
		mt.Remove(mounts[i])
	}
}

func BenchmarkMountMapRemove(b *testing.B) {
	if !enableComparativeBenchmarks {
		b.Skipf("comparative benchmarks are disabled")
	}

	mounts := make([]*Mount, 0, b.N)
	for i := 0; i < b.N; i++ {
		mounts = append(mounts, newBenchMount())
	}
	ms := make(map[VirtualDentry]*Mount)
	for i := range mounts {
		mount := mounts[i]
		ms[mount.saveKey()] = mount
	}

	b.ResetTimer()
	for i := range mounts {
		mount := mounts[i]
		delete(ms, mount.saveKey())
	}
}

func BenchmarkMountSyncMapRemove(b *testing.B) {
	if !enableComparativeBenchmarks {
		b.Skipf("comparative benchmarks are disabled")
	}

	mounts := make([]*Mount, 0, b.N)
	for i := 0; i < b.N; i++ {
		mounts = append(mounts, newBenchMount())
	}
	var ms sync.Map
	for i := range mounts {
		mount := mounts[i]
		ms.Store(mount.saveKey(), mount)
	}

	b.ResetTimer()
	for i := range mounts {
		mount := mounts[i]
		ms.Delete(mount.saveKey())
	}
}
