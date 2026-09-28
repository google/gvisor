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

package vfs

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// LandlockDomainFromCredentials returns the Landlock domain restricting creds,
// or nil if creds are unrestricted.
//
// The domain comes from the credentials an operation runs under, not from the
// calling task. E.g. overlay copying up a file under its mounter's credentials
// is not checked against the caller's domain, as ovl_override_creds() drops
// cred->security in Linux.
func LandlockDomainFromCredentials(creds *auth.Credentials) *LandlockDomain {
	domain, _ := creds.LandlockDomain.(*LandlockDomain)
	return domain
}

// LandlockRuleset is a mutable set of rules, e.g. {/usr: READ_FILE}, together
// with the rights it handles.
//
// Matches Linux [security/landlock/ruleset.h]:struct landlock_ruleset
//
// +stateify savable
type LandlockRuleset struct {
	mu              landlockRulesetMutex `state:"nosave"`
	handledAccessFS uint64

	// rules maps a file's Landlock object to the rights granted beneath it.
	// Keying by Landlock object rather than by path makes a rule follow the
	// file: a rule added for /a/dir still applies after "mv /a/dir /b/dir",
	// and through a bind mount of it. The ruleset holds a reference on each
	// Landlock object. rules is protected by mu.
	rules map[*LandlockObject]uint64
}

// NewLandlockRuleset creates a new Landlock ruleset with handledAccessFS.
// Matches Linux [security/landlock/ruleset.c]:landlock_create_ruleset()
func NewLandlockRuleset(handledAccessFS uint64) *LandlockRuleset {
	return &LandlockRuleset{
		handledAccessFS: handledAccessFS,
		rules:           make(map[*LandlockObject]uint64),
	}
}

// HandledAccessFS returns the handled filesystem access mask.
func (r *LandlockRuleset) HandledAccessFS() uint64 {
	return r.handledAccessFS
}

// InsertRule adds allowedAccess to the rule for object, taking ownership of a
// reference on object. E.g. adding READ_FILE and then WRITE_FILE for the same
// file leaves one rule granting both.
// Matches Linux [security/landlock/ruleset.c]:landlock_insert_rule()
func (r *LandlockRuleset) InsertRule(ctx context.Context, object *LandlockObject, allowedAccess uint64) {
	r.mu.Lock()
	access, ok := r.rules[object]
	r.rules[object] = access | allowedAccess
	r.mu.Unlock()
	if ok {
		// The ruleset already holds a reference for this Landlock object.
		object.DecRef(ctx)
	}
}

// release drops the ruleset's references on its Landlock objects.
//
// Matches Linux [security/landlock/ruleset.c]:free_ruleset()
func (r *LandlockRuleset) release(ctx context.Context) {
	r.mu.Lock()
	rules := r.rules
	r.rules = nil
	r.mu.Unlock()
	for object := range rules {
		object.DecRef(ctx)
	}
}

// LandlockRulesetFileDescription implements vfs.FileDescriptionImpl for anonymous Landlock ruleset file descriptors.
// Matches Linux [security/landlock/syscalls.c]:ruleset_fops
//
// +stateify savable
type LandlockRulesetFileDescription struct {
	vfsfd FileDescription
	FileDescriptionDefaultImpl
	DentryMetadataFileDescriptionImpl
	NoLockFD

	ruleset *LandlockRuleset
}

var _ FileDescriptionImpl = (*LandlockRulesetFileDescription)(nil)

// NewLandlockRulesetFD creates a new anonymous file description wrapping ruleset.
// Matches Linux [security/landlock/syscalls.c]:sys_landlock_create_ruleset()
func NewLandlockRulesetFD(ctx context.Context, vfsObj *VirtualFilesystem, ruleset *LandlockRuleset) (*FileDescription, error) {
	vd := vfsObj.NewAnonVirtualDentry("[landlock-ruleset]")
	defer vd.DecRef(ctx)

	rfd := &LandlockRulesetFileDescription{
		ruleset: ruleset,
	}
	if err := rfd.vfsfd.Init(rfd, linux.O_RDWR, auth.CredentialsFromContext(ctx), vd.Mount(), vd.Dentry(), &FileDescriptionOptions{
		UseDentryMetadata: true,
		DenyPRead:         true,
		DenyPWrite:        true,
		DenySpliceIn:      true,
	}); err != nil {
		return nil, err
	}
	return &rfd.vfsfd, nil
}

// Release implements vfs.FileDescriptionImpl.Release. Domains built from the
// ruleset are unaffected, since Merge() takes references of its own.
//
// Matches Linux [security/landlock/syscalls.c]:fop_ruleset_release()
func (rfd *LandlockRulesetFileDescription) Release(ctx context.Context) {
	rfd.ruleset.release(ctx)
}

// LandlockRulesetFromFD returns the underlying LandlockRuleset from a file description.
// Matches Linux [security/landlock/syscalls.c]:get_ruleset_from_fd()
func LandlockRulesetFromFD(file *FileDescription, requiredMode uint32) (*LandlockRuleset, error) {
	// get_ruleset_from_fd() uses fdget(), which treats O_PATH fds as closed:
	// EBADF, not EBADFD.
	if file.StatusFlags()&linux.O_PATH != 0 {
		return nil, linuxerr.EBADF
	}
	rfd, ok := file.Impl().(*LandlockRulesetFileDescription)
	if !ok {
		return nil, linuxerr.EBADFD
	}
	status := file.StatusFlags()
	if requiredMode == linux.O_WRONLY && !MayWriteFileWithOpenFlags(status) {
		return nil, linuxerr.EPERM
	}
	if requiredMode == linux.O_RDONLY && !MayReadFileWithOpenFlags(status) {
		return nil, linuxerr.EPERM
	}
	return rfd.ruleset, nil
}

// landlockLayer is the rights one layer of a domain grants beneath a file.
//
// Matches Linux [security/landlock/ruleset.h]:struct landlock_layer
//
// +stateify savable
type landlockLayer struct {
	// level is the index of the layer in LandlockDomain.handled.
	level  uint16
	access uint64
}

// LandlockDomain is an immutable stack of layers, one per
// landlock_restrict_self(2). For example, restricting a task with a ruleset
// granting READ_FILE on /usr, and then with one granting READ_FILE on /usr
// and WRITE_FILE on /tmp, gives:
//
//	handled: [READ_FILE, READ_FILE|WRITE_FILE]
//	rules:   {/usr: [{0, READ_FILE}, {1, READ_FILE}], /tmp: [{1, WRITE_FILE}]}
//
// Matches Linux [security/landlock/ruleset.h]:struct landlock_ruleset (used as a domain)
//
// +stateify savable
type LandlockDomain struct {
	// refs is the number of tasks the domain restricts; see
	// kernel.Task.SetLandlockDomain(). refs is accessed using atomic memory
	// operations.
	//
	// Credentials are not reference-counted, so credentials that outlive
	// every such task, e.g. those of an open file, may keep a released domain.
	// Rules on Landlock objects that were released with it match nothing, so
	// checks against it can only fail closed.
	refs atomicbitops.Int64

	// handled[i] is the set of rights layer i handles. handled is immutable.
	handled []uint64

	// rules maps each Landlock object that any layer has a rule for to those
	// rules, ordered by level, so that each ancestor costs one lookup however
	// many layers there are. The domain holds a reference on each Landlock
	// object. rules is immutable.
	rules map[*LandlockObject][]landlockLayer

	// parent is the domain this one was derived from, or nil. It is only
	// compared by identity, for ptrace scoping, so it holds no reference.
	// Matches Linux's struct landlock_hierarchy.
	parent *LandlockDomain
}

var _ auth.LandlockDomain = (*LandlockDomain)(nil)

// IsLandlockDomain implements auth.LandlockDomain.IsLandlockDomain.
func (d *LandlockDomain) IsLandlockDomain() {}

// ScopeLE implements auth.LandlockDomain.ScopeLE. E.g. a task in domain D may
// trace a task in D or in a domain derived from D, but not an unsandboxed task.
//
// Matches Linux [security/landlock/task.c]:domain_scope_le()
func (d *LandlockDomain) ScopeLE(other auth.LandlockDomain) bool {
	if d == nil {
		return true
	}
	child, _ := other.(*LandlockDomain)
	if child == nil {
		return false
	}
	for walker := child; walker != nil; walker = walker.parent {
		if walker == d {
			return true
		}
	}
	return false
}

// IncRef increments d's reference count. It does nothing if d is nil.
//
// Preconditions: The caller holds a reference on d.
func (d *LandlockDomain) IncRef() {
	if d == nil {
		return
	}
	if d.refs.Add(1) <= 1 {
		panic(fmt.Sprintf("LandlockDomain %p: IncRef without a reference", d))
	}
}

// DecRef decrements d's reference count, dropping its references on its
// Landlock objects when it reaches zero. It does nothing if d is nil.
//
// Matches Linux [security/landlock/ruleset.c]:landlock_put_ruleset()
func (d *LandlockDomain) DecRef(ctx context.Context) {
	if d == nil {
		return
	}
	switch r := d.refs.Add(-1); {
	case r == 0:
		for object := range d.rules {
			object.DecRef(ctx)
		}
	case r < 0:
		panic(fmt.Sprintf("LandlockDomain %p: DecRef with no references", d))
	}
}

// NumLayers returns the number of domain layers currently stacked.
func (d *LandlockDomain) NumLayers() int {
	if d == nil {
		return 0
	}
	return len(d.handled)
}

// Merge returns a new domain with ruleset stacked on top of d's layers, with
// a reference held by the caller.
//
// Linux also marks REFER handled in every layer here
// (landlock_upgrade_handled_access_masks()), which is what denies reparenting
// to every v1 domain. This implementation hardcodes that denial as
// CheckLandlockRefer()'s EXDEV instead; ABI v2 must revisit both together.
//
// Matches Linux [security/landlock/ruleset.c]:landlock_merge_ruleset()
func (d *LandlockDomain) Merge(ruleset *LandlockRuleset) (*LandlockDomain, error) {
	level := d.NumLayers()
	if level >= linux.LANDLOCK_MAX_NUM_LAYERS {
		return nil, linuxerr.E2BIG
	}

	var parentRules map[*LandlockObject][]landlockLayer
	if d != nil {
		parentRules = d.rules
	}
	ruleset.mu.Lock()
	defer ruleset.mu.Unlock()
	rules := make(map[*LandlockObject][]landlockLayer, len(parentRules)+len(ruleset.rules))
	for object, layers := range parentRules {
		object.IncRef()
		rules[object] = layers
	}
	for object, access := range ruleset.rules {
		layers, ok := rules[object]
		if !ok {
			object.IncRef()
		}
		// The three-index slice makes append copy rather than write into
		// the parent's backing array.
		rules[object] = append(layers[:len(layers):len(layers)], landlockLayer{level: uint16(level), access: access})
	}

	handled := make([]uint64, level+1)
	if d != nil {
		copy(handled, d.handled)
	}
	handled[level] = ruleset.handledAccessFS

	newDomain := &LandlockDomain{handled: handled, rules: rules, parent: d}
	newDomain.refs.Store(1)
	return newDomain, nil
}

// landlockLayerMasks tracks, per layer, the requested rights that the layer
// handles and that no rule seen so far has granted. E.g. opening a file O_RDWR
// under the domain in the LandlockDomain example starts with
// [READ_FILE, READ_FILE|WRITE_FILE]; a rule on /usr then clears READ_FILE from
// both, leaving [0, WRITE_FILE], so the open is still denied.
//
// Matches Linux [security/landlock/fs.c]:layer_masks
type landlockLayerMasks struct {
	domain *LandlockDomain

	// remaining[i] is the set of rights still to be granted by layer i.
	remaining [linux.LANDLOCK_MAX_NUM_LAYERS]uint64

	// unsatisfied is the number of layers for which remaining is non-zero.
	unsatisfied int
}

// newLayerMasks returns the initial masks for an operation requiring
// accessRights. Rights a layer does not handle start out granted.
//
// Matches Linux [security/landlock/fs.c]:init_layer_masks()
func (d *LandlockDomain) newLayerMasks(accessRights uint64) landlockLayerMasks {
	m := landlockLayerMasks{domain: d}
	for i, handled := range d.handled {
		m.remaining[i] = handled & accessRights
		if m.remaining[i] != 0 {
			m.unsatisfied++
		}
	}
	return m
}

// unmask clears the rights that the rules for object grant. object may be nil,
// for a file no rule refers to.
//
// Matches Linux [security/landlock/fs.c]:unmask_layers()
func (m *landlockLayerMasks) unmask(object *LandlockObject) {
	if object == nil {
		return
	}
	for _, layer := range m.domain.rules[object] {
		if r := &m.remaining[layer.level]; *r != 0 {
			*r &^= layer.access
			if *r == 0 {
				m.unsatisfied--
			}
		}
	}
}

// allowed reports whether every layer has granted all the rights it requires.
func (m *landlockLayerMasks) allowed() bool {
	return m.unsatisfied == 0
}

// CheckAccess returns EACCES unless every layer grants all of accessRights on
// vd. A layer grants a right if a rule on vd or any ancestor does, and rights
// add up along the way. E.g. with rules {/usr: READ_FILE, /usr/bin: EXECUTE}
// in one layer, executing /usr/bin/ls (READ_FILE|EXECUTE) is allowed.
//
// Files on internal mounts, e.g. pipes and sockets reached through
// /proc/[pid]/fd, are always allowed, since no rule can name them.
//
// References taken while walking above a mount point are appended to
// *toDecRef; see VirtualFilesystem.WalkAncestors().
//
// Matches Linux [security/landlock/fs.c]:is_access_to_paths_allowed()
func (d *LandlockDomain) CheckAccess(ctx context.Context, vfsObj *VirtualFilesystem, vd VirtualDentry, accessRights uint64, toDecRef *[]refs.RefCounter) error {
	return d.checkAccess(ctx, vfsObj, vd, nil /* leaf */, accessRights, toDecRef)
}

// CheckAccessDetached is CheckAccess for a file whose Dentry, leaf, has no
// parent, so the walk continues from vd, the directory holding it. Only mqfs
// needs this: each mq_open() gets a fresh parentless Dentry, whereas Linux
// links the queue under its mqueue mount's root.
//
// Matches Linux [security/landlock/fs.c]:is_access_to_paths_allowed()
func (d *LandlockDomain) CheckAccessDetached(ctx context.Context, vfsObj *VirtualFilesystem, leaf *Dentry, vd VirtualDentry, accessRights uint64, toDecRef *[]refs.RefCounter) error {
	return d.checkAccess(ctx, vfsObj, vd, leaf, accessRights, toDecRef)
}

// checkAccess implements CheckAccess and CheckAccessDetached.
func (d *LandlockDomain) checkAccess(ctx context.Context, vfsObj *VirtualFilesystem, vd VirtualDentry, leaf *Dentry, accessRights uint64, toDecRef *[]refs.RefCounter) error {
	if d.NumLayers() == 0 {
		return nil
	}
	if !vd.Ok() {
		return linuxerr.EACCES
	}
	// Matches is_nouser_or_private() and the MNT_INTERNAL case in Linux.
	if vd.mount.internal {
		return nil
	}

	masks := d.newLayerMasks(accessRights)
	if leaf != nil {
		masks.unmask(leaf.landlockObject())
	}
	if !masks.allowed() {
		// All layers are unmasked in a single walk.
		vfsObj.WalkAncestors(ctx, vd, toDecRef, func(dentry *Dentry) bool {
			masks.unmask(dentry.landlockObject())
			return !masks.allowed()
		})
	}
	if !masks.allowed() {
		return linuxerr.EACCES
	}
	return nil
}

// landlockOpenAccessRights returns the rights that an open with opts of a file
// of the given type requires. E.g. O_RDWR requires READ_FILE|WRITE_FILE, and
// execve(2) requires READ_FILE|EXECUTE.
//
// Matches Linux [security/landlock/fs.c]:get_required_file_open_access()
func landlockOpenAccessRights(opts *OpenOptions, isDir bool) uint64 {
	// Linux derives the rights from f_mode rather than from the access mode,
	// so the ioctl-only access mode 3 (O_ACCMODE itself; see
	// AccessTypesForOpenFlags), which is neither readable nor writable,
	// requires no right. May{Read,Write}FileWithOpenFlags() agree with f_mode.
	var accessRights uint64
	if MayReadFileWithOpenFlags(opts.Flags) {
		if isDir {
			return linux.LANDLOCK_ACCESS_FS_READ_DIR
		}
		accessRights = linux.LANDLOCK_ACCESS_FS_READ_FILE
	}
	if MayWriteFileWithOpenFlags(opts.Flags) {
		accessRights |= linux.LANDLOCK_ACCESS_FS_WRITE_FILE
	}
	if opts.FileExec {
		accessRights |= linux.LANDLOCK_ACCESS_FS_EXECUTE
	}
	return accessRights
}

// LandlockOpenAccessRights returns the rights that an open of a non-directory
// with flags requires, for filesystems that create file descriptions without
// VirtualFilesystem.OpenAt(), e.g. TIOCGPTPEER.
func LandlockOpenAccessRights(flags uint32) uint64 {
	return landlockOpenAccessRights(&OpenOptions{Flags: flags}, false)
}

// landlockModeAccess returns the right required to create a file of the given
// mode in a directory, e.g. MAKE_DIR for S_IFDIR.
//
// Matches Linux [security/landlock/fs.c]:get_mode_access()
func landlockModeAccess(mode linux.FileMode) uint64 {
	switch mode.FileType() {
	case linux.S_IFLNK:
		return linux.LANDLOCK_ACCESS_FS_MAKE_SYM
	case linux.S_IFDIR:
		return linux.LANDLOCK_ACCESS_FS_MAKE_DIR
	case linux.S_IFCHR:
		return linux.LANDLOCK_ACCESS_FS_MAKE_CHAR
	case linux.S_IFBLK:
		return linux.LANDLOCK_ACCESS_FS_MAKE_BLOCK
	case linux.S_IFIFO:
		return linux.LANDLOCK_ACCESS_FS_MAKE_FIFO
	case linux.S_IFSOCK:
		return linux.LANDLOCK_ACCESS_FS_MAKE_SOCK
	default:
		// Linux treats a zero mode as S_IFREG.
		return linux.LANDLOCK_ACCESS_FS_MAKE_REG
	}
}

// landlockRemoveAccess returns the right required to remove a file of the given
// mode from a directory.
//
// Matches Linux [security/landlock/fs.c]:maybe_remove()
func landlockRemoveAccess(mode linux.FileMode) uint64 {
	if mode.FileType() == linux.S_IFDIR {
		return linux.LANDLOCK_ACCESS_FS_REMOVE_DIR
	}
	return linux.LANDLOCK_ACCESS_FS_REMOVE_FILE
}

// Landlock checks are made by FilesystemImpls, through the ResolvingPath
// methods below, on the Dentry they resolved and under the lock they resolved
// it with. A check made by VFS would have to resolve the path again, and a
// hostile sibling thread could swap a symlink in between. Linux likewise calls
// its hooks from fs/namei.c with the resolved dentry.
//
//   - Opening an existing file checks the file, before O_TRUNC, like
//     hook_file_open().
//   - Creating, removing, renaming or linking checks the parent directory,
//     like hook_path_mknod() and its siblings. E.g. "mkdir /tmp/x" requires
//     MAKE_DIR on /tmp.
//
// Every FilesystemImpl that resolves paths must call them: tmpfs, gofer,
// overlay, kernfs and erofs do. VFS fails an open closed, and logs a mutation,
// that no check covered; see ResolvingPath.landlockChecked.

// checkLandlockAccess checks accessRights on d, which must be a Dentry on rp's
// current Mount, against the Landlock domain restricting rp's credentials.
func (rp *ResolvingPath) checkLandlockAccess(ctx context.Context, d *Dentry, accessRights uint64) error {
	rp.landlockChecked = true
	domain := LandlockDomainFromCredentials(rp.creds)
	if domain.NumLayers() == 0 {
		return nil
	}
	if d == nil {
		return linuxerr.EACCES
	}
	return domain.CheckAccess(ctx, rp.vfs, VirtualDentry{mount: rp.mount, dentry: d}, accessRights, &rp.toDecRef)
}

// LandlockRestricted reports whether a Landlock domain restricts rp's
// credentials. FilesystemImpls may skip work that only orders Landlock errors
// as Linux does, e.g. loading an unlink(2) victim so that ENOENT precedes
// EACCES, when it returns false.
func (rp *ResolvingPath) LandlockRestricted() bool {
	return LandlockDomainFromCredentials(rp.creds).NumLayers() != 0
}

// landlockUnchecked reports whether rp's credentials are restricted by a
// Landlock domain and yet the FilesystemImpl made no Landlock check.
func (rp *ResolvingPath) landlockUnchecked() bool {
	return !rp.landlockChecked && LandlockDomainFromCredentials(rp.creds).NumLayers() != 0
}

// warnIfLandlockUnchecked reports a FilesystemImpl that performed the mutation
// op without a Landlock check. Unlike an open, a mutation cannot be undone, so
// it is only logged, or panics if checkInvariants is set.
func (rp *ResolvingPath) warnIfLandlockUnchecked(op string) {
	if rp.landlockUnchecked() {
		if checkInvariants {
			panic(fmt.Sprintf("%s on %T made no Landlock check", op, rp.mount.fs.impl))
		}
		log.Warningf("%s on %T made no Landlock check", op, rp.mount.fs.impl)
	}
}

// CheckLandlockOpen checks the rights that opening d with opts requires. isDir
// is whether d is a directory.
//
// Callers must call this after CheckOpenFileType(), so that e.g. O_DIRECTORY on
// a regular file fails with ENOTDIR rather than EACCES, and before honoring
// O_TRUNC, so that a denied open leaves the file intact.
//
// Matches Linux [security/landlock/fs.c]:hook_file_open()
func (rp *ResolvingPath) CheckLandlockOpen(ctx context.Context, d *Dentry, opts *OpenOptions, isDir bool) error {
	return rp.checkLandlockAccess(ctx, d, landlockOpenAccessRights(opts, isDir))
}

// CheckLandlockOpenCreate checks the rights that creating a regular file in
// parent with opts requires. E.g. open("/tmp/f", O_CREAT|O_WRONLY) requires
// MAKE_REG|WRITE_FILE on /tmp: the new file has no rule of its own, so both
// hook_path_mknod() and hook_file_open() see only its parent's ancestry.
//
// Preconditions: The caller holds the lock under which it resolved parent, and
// has established that the file does not already exist.
//
// Matches Linux [security/landlock/fs.c]:hook_path_mknod()
func (rp *ResolvingPath) CheckLandlockOpenCreate(ctx context.Context, parent *Dentry, opts *OpenOptions) error {
	accessRights := linux.LANDLOCK_ACCESS_FS_MAKE_REG | landlockOpenAccessRights(opts, false)
	return rp.checkLandlockAccess(ctx, parent, accessRights)
}

// CheckLandlockCreate checks the right required to create a file of the given
// mode in parent.
//
// Preconditions: The caller holds the lock under which it resolved parent, and
// has established that the file does not already exist.
//
// Matches Linux [security/landlock/fs.c]:hook_path_mkdir(), hook_path_mknod()
// and hook_path_symlink()
func (rp *ResolvingPath) CheckLandlockCreate(ctx context.Context, parent *Dentry, mode linux.FileMode) error {
	return rp.checkLandlockAccess(ctx, parent, landlockModeAccess(mode))
}

// CheckLandlockMknod checks the right required to create a file of opts.Mode
// in parent, as CheckLandlockCreate does, and then, if a Landlock domain
// restricts rp's credentials, CAP_MKNOD. mknodat(2) checks CAP_MKNOD before
// the path resolves for every other task, but Linux checks it in vfs_mknod(),
// after the Landlock hook, so that e.g. an unprivileged task denied MAKE_CHAR
// gets EACCES, not EPERM. Kernel-internal callers, e.g. devtmpfs and overlay
// copy-up, are not restricted, so they are not checked here either.
//
// FilesystemImpls must call it from MknodAt() instead of CheckLandlockCreate.
//
// Preconditions: The caller holds the lock under which it resolved parent, and
// has established that the file does not already exist.
//
// Matches Linux [security/landlock/fs.c]:hook_path_mknod(), then the
// capability check in [fs/namei.c]:vfs_mknod()
func (rp *ResolvingPath) CheckLandlockMknod(ctx context.Context, parent *Dentry, opts *MknodOptions) error {
	if err := rp.CheckLandlockCreate(ctx, parent, opts.Mode); err != nil {
		return err
	}
	if !rp.LandlockRestricted() {
		return nil
	}
	return CheckMknodCapability(rp.creds, opts.Mode, opts.DevMajor, opts.DevMinor)
}

// CheckLandlockRemove checks the right required to remove a file from parent.
// isDir is whether the file being removed is a directory.
//
// Preconditions: The caller holds the lock under which it resolved parent.
//
// Matches Linux [security/landlock/fs.c]:hook_path_unlink() and
// hook_path_rmdir()
func (rp *ResolvingPath) CheckLandlockRemove(ctx context.Context, parent *Dentry, isDir bool) error {
	accessRights := uint64(linux.LANDLOCK_ACCESS_FS_REMOVE_FILE)
	if isDir {
		accessRights = linux.LANDLOCK_ACCESS_FS_REMOVE_DIR
	}
	return rp.checkLandlockAccess(ctx, parent, accessRights)
}

// LandlockReferOptions describes a rename(2) or link(2) to CheckLandlockRefer.
type LandlockReferOptions struct {
	// OldParent is the directory the source is in, and NewParent the directory
	// it is moving or being linked into. Both must be Dentries on the
	// ResolvingPath's current Mount.
	OldParent *Dentry
	NewParent *Dentry

	// SrcMode is the mode of the source file.
	SrcMode linux.FileMode

	// DstExists is whether a file is being replaced, and DstMode is its mode if
	// so.
	DstExists bool
	DstMode   linux.FileMode

	// Removable is whether the operation detaches the source from OldParent,
	// which rename(2) does and link(2) does not.
	Removable bool

	// RenameFlags are the rename(2) flags, and zero for link(2).
	RenameFlags uint32
}

// CheckLandlockRefer checks the rights that a rename(2) or link(2) described by
// opts requires.
//
// ABI v1 has no REFER right, so a sandboxed task can never move or link a file
// into another directory. For example, with MAKE_REG|REMOVE_FILE granted on
// /tmp:
//
//	rename("/tmp/a", "/tmp/b")      // allowed
//	rename("/tmp/a", "/tmp/d/a")    // EXDEV
//	rename("/tmp/a", "/usr/a")      // EACCES: /usr lacks MAKE_REG
//
// EACCES takes priority over EXDEV, so that user space only falls back to
// copying when the copy could succeed.
//
// Preconditions: The caller holds the lock under which it resolved both parents
// and determined the modes of both files.
//
// Matches Linux [security/landlock/fs.c]:current_check_refer_path()
func (rp *ResolvingPath) CheckLandlockRefer(ctx context.Context, opts *LandlockReferOptions) error {
	rp.landlockChecked = true
	if LandlockDomainFromCredentials(rp.creds).NumLayers() == 0 {
		return nil
	}

	// The rights required in the source's directory and in the destination's.
	// RENAME_EXCHANGE also moves the destination into the source's directory.
	var srcParentRights uint64
	if opts.RenameFlags&linux.RENAME_EXCHANGE != 0 {
		// FilesystemImpls return ENOENT for a missing destination before
		// getting here; this guards against a zero DstMode silently
		// requiring MAKE_REG.
		if !opts.DstExists {
			return linuxerr.ENOENT
		}
		srcParentRights = landlockModeAccess(opts.DstMode)
	}
	dstParentRights := landlockModeAccess(opts.SrcMode)
	if opts.Removable {
		srcParentRights |= landlockRemoveAccess(opts.SrcMode)
		if opts.DstExists {
			dstParentRights |= landlockRemoveAccess(opts.DstMode)
		}
	}

	if opts.OldParent == opts.NewParent {
		return rp.checkLandlockAccess(ctx, opts.NewParent, srcParentRights|dstParentRights)
	}

	// Reparenting. Linux denies it through an implicitly handled REFER bit
	// that no v1 rule can grant; that bit also disables Linux's
	// allowed_parent1 && allowed_parent2 fast path, so do not add one here.
	//
	// A zero request is allowed, as in Linux: link(2) requires nothing of the
	// source's directory, and LinkAt() passes a nil OldParent for a source
	// that is a filesystem root.
	if srcParentRights != 0 {
		if err := rp.checkLandlockAccess(ctx, opts.OldParent, srcParentRights); err != nil {
			return err
		}
	}
	if err := rp.checkLandlockAccess(ctx, opts.NewParent, dstParentRights); err != nil {
		return err
	}
	return linuxerr.EXDEV
}

// CheckLandlockMount returns EPERM if domain is active. No Landlock right
// grants mount(2), umount(2), move_mount(2) or pivot_root(2): a task that could
// e.g. bind-mount /etc over an allowed /tmp would escape its rules.
//
// Matches Linux [security/landlock/fs.c]:hook_sb_mount(), hook_move_mount(),
// hook_sb_umount(), hook_sb_remount() and hook_sb_pivotroot()
func CheckLandlockMount(domain *LandlockDomain) error {
	if domain.NumLayers() != 0 {
		return linuxerr.EPERM
	}
	return nil
}

// CheckLandlockMountAt is CheckLandlockMount for a syscall that Linux lets
// resolve its paths before the hook: each path in pops is resolved in order,
// and its error, e.g. ENOENT, takes priority over EPERM. The paths are only
// resolved when a domain is active.
//
// Matches [fs/namespace.c]:do_mount() and SYSCALL_DEFINE5(move_mount, ...),
// which resolve their paths before security_sb_mount() and
// security_move_mount().
func (vfs *VirtualFilesystem) CheckLandlockMountAt(ctx context.Context, creds *auth.Credentials, pops ...*PathOperation) error {
	return vfs.checkLandlockMountAt(ctx, creds, false /* requireDir */, pops...)
}

// CheckLandlockMountDirAt is CheckLandlockMountAt for pivot_root(2), which
// resolves its paths with LOOKUP_DIRECTORY, so ENOTDIR takes priority over
// EPERM.
func (vfs *VirtualFilesystem) CheckLandlockMountDirAt(ctx context.Context, creds *auth.Credentials, pops ...*PathOperation) error {
	return vfs.checkLandlockMountAt(ctx, creds, true /* requireDir */, pops...)
}

// checkLandlockMountAt implements CheckLandlockMountAt and
// CheckLandlockMountDirAt.
func (vfs *VirtualFilesystem) checkLandlockMountAt(ctx context.Context, creds *auth.Credentials, requireDir bool, pops ...*PathOperation) error {
	if err := CheckLandlockMount(LandlockDomainFromCredentials(creds)); err == nil {
		return nil
	}
	for _, pop := range pops {
		if requireDir {
			// Only a file known not to be a directory is rejected.
			stat, err := vfs.StatAt(ctx, creds, pop, &StatOptions{Mask: linux.STATX_TYPE})
			if err != nil {
				return err
			}
			if stat.Mask&linux.STATX_TYPE != 0 && linux.FileMode(stat.Mode).FileType() != linux.S_IFDIR {
				return linuxerr.ENOTDIR
			}
			continue
		}
		vd, err := vfs.GetDentryAt(ctx, creds, pop, &GetDentryOptions{})
		if err != nil {
			return err
		}
		vd.DecRef(ctx)
	}
	return linuxerr.EPERM
}
