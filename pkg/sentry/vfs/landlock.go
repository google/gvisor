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
