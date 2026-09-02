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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// LandlockDomainFromCredentials returns the Landlock domain restricting creds,
// or nil if creds are unrestricted.
//
// The domain is taken from the credentials an operation is performed under
// rather than from the task that requested it, so that a filesystem acting on
// its own backing files under substituted credentials is not checked against
// the calling task's domain. Matches Linux, where the domain lives in
// cred->security and so is dropped by ovl_override_creds().
func LandlockDomainFromCredentials(creds *auth.Credentials) *LandlockDomain {
	// A nil interface fails the assertion and leaves domain nil, which every
	// method below treats as unrestricted.
	domain, _ := creds.LandlockDomain.(*LandlockDomain)
	return domain
}

// LandlockRuleset represents a mutable set of Landlock rules tied to a handled access mask.
// Matches Linux [security/landlock/ruleset.h]:struct landlock_ruleset
//
// +stateify savable
type LandlockRuleset struct {
	mu              landlockRulesetMutex `state:"nosave"`
	handledAccessFS uint64

	// rules maps the file a rule was added for to the access rights granted
	// beneath it, keyed the way Linux keys rules by struct inode. A rule
	// therefore follows the file rather than the name it was added under: it
	// still applies through a hard link or a bind mount that reaches the file by
	// another path, and it survives a rename of a covered directory.
	//
	// Linux pins the struct inode a rule refers to with ihold(), so a rule can
	// never come to name a different file. An InodeIdentity is only a number, so
	// a rule can outlive the file it was added for and grant its rights over a
	// later file that inherits that number. Reaching it needs the sandboxed
	// thread to delete a file its own policy covers and then get the filesystem
	// to hand the number to a file it wants to reach.
	//
	// This is confined to filesystems that take their inode numbers from the
	// host, meaning gofer mounts and overlays stacked on one. tmpfs, kernfs and
	// erofs draw theirs from per-filesystem counters that are never reused, and
	// an identity is scoped to its filesystem, so a number cannot be confused
	// across filesystems either. The gofer already carries the same reuse in
	// fs.inoByKey, which is never pruned and so reports a single inode number
	// for both files indefinitely; a rule differs in what the confusion costs
	// rather than in how long it lasts, since a stale entry there only yields a
	// misleading st_ino while a stale rule grants access.
	rules map[InodeIdentity]uint64
}

// NewLandlockRuleset creates a new Landlock ruleset with handledAccessFS.
// Matches Linux [security/landlock/ruleset.c]:landlock_create_ruleset()
func NewLandlockRuleset(handledAccessFS uint64) *LandlockRuleset {
	return &LandlockRuleset{
		handledAccessFS: handledAccessFS,
		rules:           make(map[InodeIdentity]uint64),
	}
}

// HandledAccessFS returns the handled filesystem access mask.
func (r *LandlockRuleset) HandledAccessFS() uint64 {
	return r.handledAccessFS
}

// InsertRule adds or updates the rule for the file identified by id.
// Matches Linux [security/landlock/ruleset.c]:landlock_insert_rule()
//
// Preconditions: id.Ok().
func (r *LandlockRuleset) InsertRule(id InodeIdentity, allowedAccess uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules[id] |= allowedAccess
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
	vfsObj.landlockInUse.Store(true)

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

// Release implements vfs.FileDescriptionImpl.Release.
//
// There is nothing to release: rules are plain values that hold no references
// and no host resources. Closing the last descriptor for a ruleset cannot
// disturb any domain built from it either, since Merge() copies the rules it
// takes rather than keeping the ruleset. The ruleset is reclaimed by the
// garbage collector once nothing refers to it.
//
// Matches gVisor [pkg/sentry/vfs/file_description.go]:[FileDescriptionImpl.Release]()
func (rfd *LandlockRulesetFileDescription) Release(ctx context.Context) {
}

// LandlockInUse returns whether a Landlock ruleset has ever been created.
// FilesystemImpls whose inode identities could be reused consult this to
// decide whether identities must be retired when files are deleted; until a
// ruleset exists, no rule can be keyed by one, so a recycled identity costs
// nothing more than a misleading st_ino.
func (vfs *VirtualFilesystem) LandlockInUse() bool {
	return vfs.landlockInUse.Load()
}

// LandlockRulesetFromFD returns the underlying LandlockRuleset from a file description.
// Matches Linux [security/landlock/syscalls.c]:get_ruleset_from_fd()
func LandlockRulesetFromFD(file *FileDescription, requiredMode uint32) (*LandlockRuleset, error) {
	rfd, ok := file.Impl().(*LandlockRulesetFileDescription)
	if !ok {
		return nil, linuxerr.EBADFD
	}
	status := file.StatusFlags()
	if requiredMode == linux.O_WRONLY && (status&linux.O_ACCMODE) == linux.O_RDONLY {
		return nil, linuxerr.EPERM
	}
	if requiredMode == linux.O_RDONLY && (status&linux.O_ACCMODE) == linux.O_WRONLY {
		return nil, linuxerr.EPERM
	}
	return rfd.ruleset, nil
}

// LandlockDomainLayer represents a snapshot of a ruleset's rules at enforcement time.
// Matches Linux [security/landlock/ruleset.h]:struct landlock_layer
//
// +stateify savable
type LandlockDomainLayer struct {
	handledAccessFS uint64
	rules           map[InodeIdentity]uint64
}

// LandlockDomain represents an immutable stacked hierarchy of Landlock domain layers.
// Matches Linux [security/landlock/ruleset.h]:struct landlock_ruleset (used as a domain)
//
// +stateify savable
type LandlockDomain struct {
	layers []LandlockDomainLayer

	// parent is the domain this one was derived from, or nil if this is the
	// first domain enforced on a thread. The resulting chain mirrors Linux's
	// struct landlock_hierarchy, which exists so that ptrace scoping can ask
	// whether one domain is an ancestor of another.
	parent *LandlockDomain
}

var _ auth.LandlockDomain = (*LandlockDomain)(nil)

// IsLandlockDomain implements auth.LandlockDomain.IsLandlockDomain.
func (d *LandlockDomain) IsLandlockDomain() {}

// ScopeLE implements auth.LandlockDomain.ScopeLE.
//
// Matches Linux [security/landlock/task.c]:domain_scope_le()
func (d *LandlockDomain) ScopeLE(other auth.LandlockDomain) bool {
	// A task with no domain is not restricted in whom it may trace.
	if d == nil {
		return true
	}
	child, _ := other.(*LandlockDomain)
	// An unsandboxed target is never within a sandboxed tracer's hierarchy.
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

// NumLayers returns the number of domain layers currently stacked.
func (d *LandlockDomain) NumLayers() int {
	if d == nil {
		return 0
	}
	return len(d.layers)
}

// Merge merges a ruleset into a new stacked LandlockDomain layer.
// Matches Linux [security/landlock/ruleset.c]:landlock_merge_ruleset()
func (d *LandlockDomain) Merge(ruleset *LandlockRuleset) (*LandlockDomain, error) {
	currentLayers := 0
	if d != nil {
		currentLayers = len(d.layers)
	}
	if currentLayers >= linux.LANDLOCK_MAX_NUM_LAYERS {
		return nil, linuxerr.E2BIG
	}

	ruleset.mu.Lock()
	snapshotRules := make(map[InodeIdentity]uint64, len(ruleset.rules))
	for k, v := range ruleset.rules {
		snapshotRules[k] = v
	}
	// Linux additionally ORs _LANDLOCK_ACCESS_FS_INITIALLY_DENIED (== REFER)
	// into every layer's handled mask here, via
	// landlock_upgrade_handled_access_masks(): that implicit always-handled,
	// never-grantable bit is what makes its generic evaluation deny
	// cross-directory rename/link for every domain. This implementation
	// deliberately omits the upgrade and instead hardcodes that denial as
	// CheckLandlockRefer()'s EXDEV tail, which is equivalent for ABI v1.
	// Whoever adds LANDLOCK_ACCESS_FS_REFER (ABI v2) must revisit both
	// places together: with REFER merely added to LANDLOCK_ACCESS_FS_V1,
	// a layer that does not handle it would auto-satisfy it in
	// newLayerMasks(), inverting the default into allow.
	newLayer := LandlockDomainLayer{
		handledAccessFS: ruleset.handledAccessFS,
		rules:           snapshotRules,
	}
	ruleset.mu.Unlock()

	newLayers := make([]LandlockDomainLayer, currentLayers+1)
	if currentLayers > 0 {
		copy(newLayers, d.layers)
	}
	newLayers[currentLayers] = newLayer

	return &LandlockDomain{layers: newLayers, parent: d}, nil
}

// landlockLayerMasks tracks, for each layer of a domain, the access rights that
// the layer requires for an operation and that no rule seen so far has granted.
//
// Matches Linux [security/landlock/fs.c]:struct access_masks used as
// layer_masks
type landlockLayerMasks struct {
	domain *LandlockDomain

	// remaining[i] is the set of rights still to be granted by layer i.
	remaining []uint64

	// unsatisfied is the number of layers for which remaining is non-zero.
	unsatisfied int
}

// newLayerMasks returns the initial per-layer masks for an operation requiring
// accessRights. A layer only constrains the rights it handles, so rights it
// does not handle start out satisfied.
//
// Matches Linux [security/landlock/fs.c]:init_layer_masks()
func (d *LandlockDomain) newLayerMasks(accessRights uint64) landlockLayerMasks {
	m := landlockLayerMasks{
		domain:    d,
		remaining: make([]uint64, len(d.layers)),
	}
	for i, layer := range d.layers {
		m.remaining[i] = layer.handledAccessFS & accessRights
		if m.remaining[i] != 0 {
			m.unsatisfied++
		}
	}
	return m
}

// unmask clears from every layer the rights that the rule for id grants.
//
// Matches Linux [security/landlock/fs.c]:unmask_layers()
func (m *landlockLayerMasks) unmask(id InodeIdentity) {
	if !id.Ok() {
		return
	}
	for i := range m.domain.layers {
		if m.remaining[i] == 0 {
			continue
		}
		m.remaining[i] &^= m.domain.layers[i].rules[id]
		if m.remaining[i] == 0 {
			m.unsatisfied--
		}
	}
}

// allowed reports whether every layer has granted all the rights it requires.
func (m *landlockLayerMasks) allowed() bool {
	return m.unsatisfied == 0
}

// CheckAccess evaluates whether all of accessRights on vd are allowed by every
// layer of the domain.
//
// Within a layer, a right is granted if vd or any of its ancestors has a rule
// granting it, and rights accumulate across ancestors. All of the rights that a
// layer handles must be granted for that layer to allow the access.
//
// Files on internal mounts are always allowed. No rule can ever name them,
// since such a mount cannot appear in a path, so denying them would make files
// reached through /proc/[pid]/fd and /proc/[pid]/ns unusable under any domain
// rather than merely unnamable.
//
// If vd names no file, access is denied: what cannot be checked against the
// domain's rules must fail closed.
//
// References taken while walking above a mount point are appended to *toDecRef
// for the caller to drop once it holds no filesystem locks. See
// VirtualFilesystem.WalkAncestors().
//
// Matches Linux [security/landlock/fs.c]:is_access_to_paths_allowed()
func (d *LandlockDomain) CheckAccess(ctx context.Context, vfsObj *VirtualFilesystem, vd VirtualDentry, accessRights uint64, toDecRef *[]refs.RefCounter) error {
	return d.checkAccess(ctx, vfsObj, vd, InodeIdentity{}, accessRights, toDecRef)
}

// CheckAccessDetached is CheckAccess for a file that its filesystem has not
// linked into its own tree, so that nothing above the file can be reached from
// it. id identifies the file, and vd names the directory holding it, which the
// ancestry is walked from instead.
//
// Only mqfs needs this: it gives every message queue file description a fresh
// parentless Dentry, so a walk from that Dentry would see the queue and stop.
// Linux has no such gap, since it links the queue dentry under the root of the
// IPC namespace's internal mqueue mount and walks up from there.
//
// Matches Linux [security/landlock/fs.c]:is_access_to_paths_allowed()
func (d *LandlockDomain) CheckAccessDetached(ctx context.Context, vfsObj *VirtualFilesystem, id InodeIdentity, vd VirtualDentry, accessRights uint64, toDecRef *[]refs.RefCounter) error {
	return d.checkAccess(ctx, vfsObj, vd, id, accessRights, toDecRef)
}

// checkAccess implements CheckAccess and CheckAccessDetached. leaf, if it names
// a file, is consulted before the walk from vd begins, as the first iteration
// of Linux's loop consults the dentry that the walk starts from.
func (d *LandlockDomain) checkAccess(ctx context.Context, vfsObj *VirtualFilesystem, vd VirtualDentry, leaf InodeIdentity, accessRights uint64, toDecRef *[]refs.RefCounter) error {
	if d == nil || len(d.layers) == 0 {
		return nil
	}
	if !vd.Ok() {
		return linuxerr.EACCES
	}
	// Matches the is_nouser_or_private() early return in Linux's
	// is_access_to_paths_allowed(), together with its MNT_INTERNAL case for
	// disconnected roots: both allow, and in gVisor both are exactly the files
	// living on an internal mount.
	if vd.mount.internal {
		return nil
	}

	masks := d.newLayerMasks(accessRights)
	masks.unmask(leaf)
	if masks.allowed() {
		// No layer handles any of the requested rights, or a rule on leaf
		// grants all of the ones that are handled.
		return nil
	}

	// All layers are unmasked together so that the ancestry is walked once
	// rather than once per layer.
	vfsObj.WalkAncestors(ctx, vd, toDecRef, func(dentry *Dentry) bool {
		masks.unmask(dentry.InodeIdentity())
		return !masks.allowed()
	})

	if !masks.allowed() {
		return linuxerr.EACCES
	}
	return nil
}

// landlockOpenAccessRights returns the filesystem access rights that an open
// with opts of a file of the given type requires.
//
// Matches Linux [security/landlock/fs.c]:get_required_file_open_access(), which
// derives the required rights from the resulting file's f_mode, so that O_RDWR
// requires both read and write.
func landlockOpenAccessRights(opts *OpenOptions, isDir bool) uint64 {
	// Linux reads the rights off the resulting file's f_mode, which
	// OPEN_FMODE() derives from the access mode as ((flags + 1) & O_ACCMODE).
	// The fourth access mode, which open(2) accepts and which asks for a file
	// that is neither readable nor writable, therefore requires no right at
	// all. Switching on the access mode instead would give that mode whatever
	// the default case grants.
	const fmodeRead, fmodeWrite = 0x1, 0x2
	fmode := (opts.Flags + 1) & linux.O_ACCMODE

	var accessRights uint64
	if fmode&fmodeRead != 0 {
		if isDir {
			// Linux returns here without consulting the write bit: a directory
			// can only be opened in read mode, so READ_DIR is the only right it
			// can require.
			return linux.LANDLOCK_ACCESS_FS_READ_DIR
		}
		accessRights = linux.LANDLOCK_ACCESS_FS_READ_FILE
	}
	if fmode&fmodeWrite != 0 {
		accessRights |= linux.LANDLOCK_ACCESS_FS_WRITE_FILE
	}
	// EXECUTE is required in addition to the rights the access mode implies,
	// not instead of them. execve(2) opens the file with O_RDONLY, so
	// FMODE_READ is set and Linux requires READ_FILE as well. Returning
	// EXECUTE alone would let a domain that handles READ_FILE but not EXECUTE
	// execute any file, since no layer would then handle any requested right.
	if opts.FileExec {
		accessRights |= linux.LANDLOCK_ACCESS_FS_EXECUTE
	}
	return accessRights
}

// LandlockOpenAccessRights returns the filesystem access rights that an open of
// a non-directory with the given open flags requires.
//
// This is for filesystems that create file descriptions without going through
// VirtualFilesystem.OpenAt(), which checks the domain itself.
func LandlockOpenAccessRights(flags uint32) uint64 {
	return landlockOpenAccessRights(&OpenOptions{Flags: flags}, false)
}

// landlockModeAccess returns the right required to create a file of the given
// mode in a directory.
//
// Matches Linux [security/landlock/fs.c]:get_mode_access()
func landlockModeAccess(mode linux.FileMode) uint64 {
	switch mode & linux.S_IFMT {
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

// Landlock checks are performed by FilesystemImpls rather than by VFS, through
// the methods on ResolvingPath below.
//
// A check must be evaluated against the very Dentry that the operation acts on.
// VFS only has a pathname, so a check it performed itself would have to resolve
// that pathname a second time, and the two resolutions can disagree: Landlock's
// threat model is a sandboxed thread whose siblings are hostile, and a sibling
// is free to swap a symlink or a name between them. Linux has the same
// requirement and meets it the same way, by calling the LSM hook from inside
// fs/namei.c with the resolved dentry in hand rather than from the syscall
// entry point with the pathname.
//
// Where the check falls therefore differs by operation, mirroring the hook
// Linux uses:
//
//   - An open of an existing file is checked against the file itself, once it
//     is resolved and before it is truncated, like hook_file_open().
//
//   - Creating, removing, renaming or linking a file is checked against the
//     directory it happens in, before it happens and while the FilesystemImpl
//     still holds the lock under which it resolved that directory, like
//     hook_path_mknod() and its siblings. Holding the lock is what makes the
//     check and the operation agree on what the final component names.
//
// A FilesystemImpl that resolves paths and does not call these is not checked,
// so any new one must. As of this writing the implementations that need them
// are tmpfs, gofer, overlay, kernfs and erofs; anonfs resolves nothing and
// refuses every operation these guard.

// checkLandlockAccess checks accessRights on d, which must be a Dentry on rp's
// current Mount, against the Landlock domain restricting rp's credentials.
func (rp *ResolvingPath) checkLandlockAccess(ctx context.Context, d *Dentry, accessRights uint64) error {
	domain := LandlockDomainFromCredentials(rp.creds)
	if domain.NumLayers() == 0 {
		return nil
	}
	if d == nil {
		// No file to check the domain's rules against, so fail closed.
		return linuxerr.EACCES
	}
	return domain.CheckAccess(ctx, rp.vfs, VirtualDentry{mount: rp.mount, dentry: d}, accessRights, &rp.toDecRef)
}

// CheckLandlockOpen checks the rights that opening d with opts requires. isDir
// is whether d is a directory.
//
// Callers must call this after resolving d and before honoring O_TRUNC, so that
// a denied open leaves the file as it was, and after CheckOpenFileType(), so
// that an open no file of that type could satisfy reports why rather than
// EACCES.
//
// Matches Linux [security/landlock/fs.c]:hook_file_open(), which runs from
// do_dentry_open() and so precedes the handle_truncate() in do_open().
func (rp *ResolvingPath) CheckLandlockOpen(ctx context.Context, d *Dentry, opts *OpenOptions, isDir bool) error {
	return rp.checkLandlockAccess(ctx, d, landlockOpenAccessRights(opts, isDir))
}

// CheckLandlockOpenCreate checks the rights that an open with opts requires to
// create a regular file in parent.
//
// Preconditions: The caller holds the lock under which it resolved parent, and
// has established that the file does not already exist.
//
// Matches Linux [security/landlock/fs.c]:hook_path_mknod()
func (rp *ResolvingPath) CheckLandlockOpenCreate(ctx context.Context, parent *Dentry, opts *OpenOptions) error {
	// hook_path_mknod() requires the right to create the file, and
	// hook_file_open() then requires the rights its access mode implies. Both
	// are evaluated against the parent directory: the file is about to come into
	// existence, so no rule names it, and its ancestry is its parent's. Because
	// the two draw on the same ancestry, requiring their union in one walk
	// accepts exactly the same operations as checking them one after the other.
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
// Landlock ABI v1 has no LANDLOCK_ACCESS_FS_REFER right, and Linux denies REFER
// by default even to a domain that does not handle it, so a sandboxed thread
// can never move or link a file between two different directories. It still
// matters which error says so: Linux reports EACCES if the policy denies a
// right other than REFER in either directory, and EXDEV only if the sole
// missing right is REFER. current_check_refer_path() calls that out —
// "Prioritizing EACCES over EXDEV enables user space to abort the whole
// operation if there is no way to do it, or to manually copy the source to the
// destination if this remains allowed".
//
// Preconditions: The caller holds the lock under which it resolved both parents
// and determined the modes of both files.
//
// Matches Linux [security/landlock/fs.c]:current_check_refer_path()
func (rp *ResolvingPath) CheckLandlockRefer(ctx context.Context, opts *LandlockReferOptions) error {
	if LandlockDomainFromCredentials(rp.creds).NumLayers() == 0 {
		return nil
	}

	// Linux's access_request_parent1 and access_request_parent2: the rights
	// required in the directory the source leaves and in the one it arrives
	// in. RENAME_EXCHANGE moves the destination into the source's directory,
	// so that directory must be allowed to create a file of its type too.
	var srcParentRights uint64
	if opts.RenameFlags&linux.RENAME_EXCHANGE != 0 {
		// An exchange needs a destination. The FilesystemImpl reports ENOENT
		// for one that does not exist before it gets here, as do_renameat2()
		// does before the hook, so this is belt and suspenders: without it, a
		// zero DstMode would silently become a spurious MAKE_REG requirement.
		//
		// Matches Linux [security/landlock/fs.c]:current_check_refer_path()
		// checking d_is_negative(new_dentry).
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
		// REFER is not required for a same-directory refer, and both sets of
		// rights are required in the same directory, so checking their union
		// in one walk accepts exactly the same operations as two walks.
		return rp.checkLandlockAccess(ctx, opts.NewParent, srcParentRights|dstParentRights)
	}

	// Reparenting, which REFER would have to allow and no v1 domain can grant.
	// In Linux this denial is not special-cased: every domain implicitly
	// handles REFER (_LANDLOCK_ACCESS_FS_INITIALLY_DENIED, ORed in by
	// landlock_upgrade_handled_access_masks() at merge time), no v1 rule can
	// grant it, so the generic evaluation leaves it unsatisfied. The implicit
	// bit is also why Linux's allowed_parent1 && allowed_parent2 fast path
	// never fires for a v1 domain; do not add such a fast path here without
	// modeling the bit, or a domain granting all its handled rights on a
	// common ancestor would allow reparenting beneath it.
	// Report EACCES if either directory is missing a right it needs anyway,
	// which is what is_eacces() computes in Linux from the layer masks left
	// over after the two hierarchy walks; those masks hold exactly the
	// requested rights no rule granted, so the ordinary check of each request
	// against its own directory decides it.
	//
	// A zero request is allowed in Linux, where landlock_init_layer_masks()
	// reports no handled access for it. That matters here because link(2)
	// requires nothing of the directory the source stays in, and may not even
	// have one: LinkAt() leaves OldParent nil for a source that is a
	// filesystem root.
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

// CheckLandlockMount denies a change to the mount tree while domain is active.
//
// Landlock has no right that grants these operations, so a sandboxed thread
// cannot perform them at all, whatever rights its domain handles or grants.
// Denying them is also what keeps the rest of the policy meaningful: a thread
// that could rearrange the mount tree could bring a file it is allowed to
// access into a path it is not, or hide one behind a mount of its own.
//
// Matches Linux [security/landlock/fs.c]:hook_sb_mount(), hook_move_mount(),
// hook_sb_umount(), hook_sb_remount() and hook_sb_pivotroot(), all of which
// return -EPERM whenever a domain is active.
func CheckLandlockMount(domain *LandlockDomain) error {
	if domain.NumLayers() != 0 {
		return linuxerr.EPERM
	}
	return nil
}

// CheckLandlockMountAt is CheckLandlockMount for a syscall that Linux lets
// resolve its paths before reaching the hook. Each path in pops is resolved, in
// the order Linux resolves them, and the first one that cannot be is reported
// instead of the denial; only a call whose paths all resolve is denied.
//
// The paths are resolved only when a domain is active, so an allowed call still
// walks each path exactly once, in the operation itself.
//
// Linux resolves them in the syscall, before the hook the operation runs:
// [fs/namespace.c]:do_mount() resolves the mount point before path_mount()
// calls security_sb_mount(), and SYSCALL_DEFINE5(move_mount, ...) resolves the
// destination and then the source before vfs_move_mount() calls
// security_move_mount().
func (vfs *VirtualFilesystem) CheckLandlockMountAt(ctx context.Context, creds *auth.Credentials, pops ...*PathOperation) error {
	return vfs.checkLandlockMountAt(ctx, creds, false /* requireDir */, pops...)
}

// CheckLandlockMountDirAt is CheckLandlockMountAt for operations whose Linux
// counterpart resolves the paths with LOOKUP_DIRECTORY before the Landlock
// hook (pivot_root), so that ENOTDIR takes priority over EPERM.
//
// SYSCALL_DEFINE2(pivot_root, ...) resolves both directories that way before
// path_pivot_root() calls security_sb_pivotroot().
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
			// LOOKUP_DIRECTORY makes resolution itself fail with ENOTDIR for a
			// path naming a non-directory, so the type is checked here rather
			// than left to the operation, which never runs for a denied call.
			// A filesystem that cannot report the type is given the benefit of
			// the doubt; only a file known not to be a directory is rejected.
			stat, err := vfs.StatAt(ctx, creds, pop, &StatOptions{Mask: linux.STATX_TYPE})
			if err != nil {
				return err
			}
			if stat.Mask&linux.STATX_TYPE != 0 && stat.Mode&linux.S_IFMT != linux.S_IFDIR {
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
