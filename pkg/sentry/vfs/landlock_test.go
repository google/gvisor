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
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// The files these tests refer to, named by inode number. There is no filesystem
// here: a test states an ancestry directly rather than deriving it from a path.
const (
	inoRoot = iota + 1
	inoA
	inoB
	inoC
	inoOther
)

// testObjects are the Landlock objects of the files above. They are created
// directly rather than for a Dentry: the check only compares Landlock objects,
// so tests of it need no filesystem. Each holds one reference on behalf of the
// test package, which is never dropped.
var testObjects = func() map[uint64]*LandlockObject {
	m := make(map[uint64]*LandlockObject)
	for ino := uint64(inoRoot); ino <= inoOther; ino++ {
		o := &LandlockObject{}
		o.refs.Store(1)
		m[ino] = o
	}
	return m
}()

// id returns the Landlock object of the file numbered ino, with a new
// reference.
func id(ino uint64) *LandlockObject {
	o := testObjects[ino]
	o.IncRef()
	return o
}

// ids returns the Landlock objects of the files numbered inos, as they are
// found in an ancestry walk. No references are taken.
func ids(inos ...uint64) []*LandlockObject {
	out := make([]*LandlockObject, 0, len(inos))
	for _, ino := range inos {
		out = append(out, testObjects[ino])
	}
	return out
}

// rulesetWith returns a ruleset handling handled, with a rule for each file in
// rules granting the rights it maps to.
func rulesetWith(handled uint64, rules map[uint64]uint64) *LandlockRuleset {
	rs := NewLandlockRuleset(handled)
	for ino, access := range rules {
		rs.InsertRule(context.Background(), id(ino), access)
	}
	return rs
}

// domainWith returns a domain formed by merging rulesets in order.
func domainWith(t *testing.T, rulesets ...*LandlockRuleset) *LandlockDomain {
	t.Helper()
	var d *LandlockDomain
	for i, rs := range rulesets {
		next, err := d.Merge(rs)
		if err != nil {
			t.Fatalf("Merge(layer %d) failed: %v", i, err)
		}
		d = next
	}
	return d
}

// checkAncestry evaluates accessRights against d over ancestry, which lists the
// file being accessed followed by its ancestors in order.
//
// This is what CheckAccess does once VirtualFilesystem.WalkAncestors has
// produced the ancestry; the walk itself needs a mount tree and is covered by
// the syscall tests.
func checkAncestry(d *LandlockDomain, ancestry []*LandlockObject, accessRights uint64) error {
	if d.NumLayers() == 0 {
		return nil
	}
	masks := d.newLayerMasks(accessRights)
	for _, ancestor := range ancestry {
		if masks.allowed() {
			break
		}
		masks.unmask(ancestor)
	}
	if !masks.allowed() {
		return linuxerr.EACCES
	}
	return nil
}

func TestLandlockCheckAccess(t *testing.T) {
	const (
		read  = linux.LANDLOCK_ACCESS_FS_READ_FILE
		write = linux.LANDLOCK_ACCESS_FS_WRITE_FILE
		rdDir = linux.LANDLOCK_ACCESS_FS_READ_DIR
	)

	// In each case, layers are the rulesets to merge, outermost first, and
	// ancestry is the file being accessed followed by its ancestors.
	for _, test := range []struct {
		name     string
		layers   []*LandlockRuleset
		ancestry []*LandlockObject
		rights   uint64
		allowed  bool
	}{
		{
			name:     "rule on the file itself grants access",
			layers:   []*LandlockRuleset{rulesetWith(read, map[uint64]uint64{inoB: read})},
			ancestry: ids(inoB, inoA, inoRoot),
			rights:   read,
			allowed:  true,
		},
		{
			name:     "rule on an ancestor grants access beneath it",
			layers:   []*LandlockRuleset{rulesetWith(read, map[uint64]uint64{inoA: read})},
			ancestry: ids(inoC, inoB, inoA, inoRoot),
			rights:   read,
			allowed:  true,
		},
		{
			name:     "no covering rule denies access",
			layers:   []*LandlockRuleset{rulesetWith(read, map[uint64]uint64{inoA: read})},
			ancestry: ids(inoOther, inoRoot),
			rights:   read,
			allowed:  false,
		},
		{
			// A rule applies to the file it names and what lies beneath it, not
			// to a file that merely shares an ancestor with it.
			name:     "a sibling is not an ancestor",
			layers:   []*LandlockRuleset{rulesetWith(read, map[uint64]uint64{inoA: read})},
			ancestry: ids(inoB, inoRoot),
			rights:   read,
			allowed:  false,
		},
		{
			name:     "unhandled rights are unconstrained",
			layers:   []*LandlockRuleset{rulesetWith(read, map[uint64]uint64{inoA: read})},
			ancestry: ids(inoOther, inoRoot),
			rights:   write,
			allowed:  true,
		},
		{
			name:     "a right the rule omits is denied",
			layers:   []*LandlockRuleset{rulesetWith(read|write, map[uint64]uint64{inoA: read})},
			ancestry: ids(inoB, inoA, inoRoot),
			rights:   write,
			allowed:  false,
		},
		{
			// O_RDWR requires both rights; granting only one is not enough.
			name:     "all requested rights must be granted",
			layers:   []*LandlockRuleset{rulesetWith(read|write, map[uint64]uint64{inoA: read})},
			ancestry: ids(inoB, inoA, inoRoot),
			rights:   read | write,
			allowed:  false,
		},
		{
			name:     "both requested rights granted by one rule",
			layers:   []*LandlockRuleset{rulesetWith(read|write, map[uint64]uint64{inoA: read | write})},
			ancestry: ids(inoB, inoA, inoRoot),
			rights:   read | write,
			allowed:  true,
		},
		{
			// Linux's unmask_layers() clears rights as it walks up, so rights
			// granted by different ancestors combine.
			name: "rights accumulate across ancestors",
			layers: []*LandlockRuleset{rulesetWith(read|write, map[uint64]uint64{
				inoA: read,
				inoB: write,
			})},
			ancestry: ids(inoC, inoB, inoA, inoRoot),
			rights:   read | write,
			allowed:  true,
		},
		{
			name: "layers intersect: denied by the second layer",
			layers: []*LandlockRuleset{
				rulesetWith(read, map[uint64]uint64{inoA: read}),
				rulesetWith(read, map[uint64]uint64{inoB: read}),
			},
			ancestry: ids(inoC, inoA, inoRoot),
			rights:   read,
			allowed:  false,
		},
		{
			name: "layers intersect: allowed by both layers",
			layers: []*LandlockRuleset{
				rulesetWith(read, map[uint64]uint64{inoA: read}),
				rulesetWith(read, map[uint64]uint64{inoB: read}),
			},
			ancestry: ids(inoC, inoB, inoA, inoRoot),
			rights:   read,
			allowed:  true,
		},
		{
			// Rules for the same inode in different layers stay in their
			// layers: each layer must grant every right on its own, as
			// landlock_insert_rule() keeps per-layer rule copies distinct
			// during a merge. A merge that unioned same-inode rules across
			// layers would allow this.
			name: "same inode in two layers: rights intersect, not union",
			layers: []*LandlockRuleset{
				rulesetWith(read|write, map[uint64]uint64{inoA: read}),
				rulesetWith(read|write, map[uint64]uint64{inoA: write}),
			},
			ancestry: ids(inoB, inoA, inoRoot),
			rights:   read | write,
			allowed:  false,
		},
		{
			name: "same inode in two layers: both grant the right",
			layers: []*LandlockRuleset{
				rulesetWith(read|write, map[uint64]uint64{inoA: read}),
				rulesetWith(read|write, map[uint64]uint64{inoA: read}),
			},
			ancestry: ids(inoB, inoA, inoRoot),
			rights:   read,
			allowed:  true,
		},
		{
			// A layer already satisfied at a deeper ancestor must stay
			// satisfied, not double-count, when a higher rule grants the same
			// rights again while another layer is still waiting on it.
			name: "a second grant to a satisfied layer is harmless",
			layers: []*LandlockRuleset{
				rulesetWith(read, map[uint64]uint64{inoB: read, inoA: read}),
				rulesetWith(read, map[uint64]uint64{inoA: read}),
			},
			ancestry: ids(inoC, inoB, inoA, inoRoot),
			rights:   read,
			allowed:  true,
		},
		{
			name: "a later layer only handling other rights does not deny",
			layers: []*LandlockRuleset{
				rulesetWith(read, map[uint64]uint64{inoA: read}),
				rulesetWith(rdDir, map[uint64]uint64{inoB: rdDir}),
			},
			ancestry: ids(inoC, inoA, inoRoot),
			rights:   read,
			allowed:  true,
		},
		{
			name:     "a rule on the root covers everything",
			layers:   []*LandlockRuleset{rulesetWith(read, map[uint64]uint64{inoRoot: read})},
			ancestry: ids(inoC, inoB, inoA, inoRoot),
			rights:   read,
			allowed:  true,
		},
		{
			// A file whose filesystem cannot name it matches no rule, so an
			// unnameable ancestor neither grants nor blocks anything.
			name:     "an ancestor with no Landlock object is skipped",
			layers:   []*LandlockRuleset{rulesetWith(read, map[uint64]uint64{inoA: read})},
			ancestry: []*LandlockObject{testObjects[inoB], nil, testObjects[inoA], testObjects[inoRoot]},
			rights:   read,
			allowed:  true,
		},
		{
			// Failing closed is what makes an unnameable file safe: it can only
			// be reached if some nameable ancestor of it grants the rights.
			name:     "a file with no Landlock object and no covering rule is denied",
			layers:   []*LandlockRuleset{rulesetWith(read, map[uint64]uint64{inoA: read})},
			ancestry: []*LandlockObject{nil},
			rights:   read,
			allowed:  false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := domainWith(t, test.layers...)
			err := checkAncestry(d, test.ancestry, test.rights)
			if got := err == nil; got != test.allowed {
				t.Errorf("checkAncestry(%v, %#x) = %v, want allowed=%v", test.ancestry, test.rights, err, test.allowed)
			}
			if err != nil && !linuxerr.Equals(linuxerr.EACCES, err) {
				t.Errorf("checkAncestry(%v, %#x) = %v, want EACCES", test.ancestry, test.rights, err)
			}
		})
	}
}

func TestLandlockCheckAccessNilDomain(t *testing.T) {
	var d *LandlockDomain
	if err := checkAncestry(d, ids(inoA), linux.LANDLOCK_ACCESS_FS_READ_FILE); err != nil {
		t.Errorf("checkAncestry on nil domain = %v, want nil", err)
	}
	if got := d.NumLayers(); got != 0 {
		t.Errorf("NumLayers on nil domain = %d, want 0", got)
	}
}

// TestLandlockRuleUnionsRights verifies that adding a second rule for a file
// grants the union of the two, matching Linux's landlock_insert_rule().
func TestLandlockRuleUnionsRights(t *testing.T) {
	const (
		read  = linux.LANDLOCK_ACCESS_FS_READ_FILE
		write = linux.LANDLOCK_ACCESS_FS_WRITE_FILE
	)

	rs := NewLandlockRuleset(read | write)
	rs.InsertRule(context.Background(), id(inoA), read)
	rs.InsertRule(context.Background(), id(inoA), write)
	d := domainWith(t, rs)

	if err := checkAncestry(d, ids(inoB, inoA), read|write); err != nil {
		t.Errorf("checkAncestry = %v, want nil: rights from both rules must apply", err)
	}
}

// TestLandlockRuleFollowsTheFile verifies that a rule is keyed by the file
// rather than by any one name for it, so that a second name for the same file
// reaches the same rule. This is what Linux gets from keying on struct inode.
func TestLandlockRuleFollowsTheFile(t *testing.T) {
	const read = linux.LANDLOCK_ACCESS_FS_READ_FILE

	d := domainWith(t, rulesetWith(read, map[uint64]uint64{inoA: read}))

	// inoA reached as a hard link under a different directory.
	if err := checkAncestry(d, ids(inoA, inoC, inoRoot), read); err != nil {
		t.Errorf("checkAncestry via a second name = %v, want nil", err)
	}
	// The same file reached with no shared ancestor at all, as through a bind
	// mount elsewhere in the tree.
	if err := checkAncestry(d, ids(inoA), read); err != nil {
		t.Errorf("checkAncestry with no shared ancestor = %v, want nil", err)
	}
}

// TestLandlockMergeSnapshotsRules verifies that rules added to a ruleset after
// it has been merged into a domain do not affect that domain, matching Linux's
// landlock_merge_ruleset().
func TestLandlockMergeSnapshotsRules(t *testing.T) {
	const read = linux.LANDLOCK_ACCESS_FS_READ_FILE

	rs := rulesetWith(read, map[uint64]uint64{inoA: read})
	d := domainWith(t, rs)

	rs.InsertRule(context.Background(), id(inoB), read)

	if err := checkAncestry(d, ids(inoC, inoB), read); err == nil {
		t.Error("checkAncestry = nil, want EACCES: rule added after merge must not apply")
	}
}

func TestLandlockMergeLayerLimit(t *testing.T) {
	const read = linux.LANDLOCK_ACCESS_FS_READ_FILE

	var d *LandlockDomain
	for i := 0; i < linux.LANDLOCK_MAX_NUM_LAYERS; i++ {
		next, err := d.Merge(rulesetWith(read, map[uint64]uint64{inoRoot: read}))
		if err != nil {
			t.Fatalf("Merge(layer %d) = %v, want nil", i, err)
		}
		d = next
	}
	if got := d.NumLayers(); got != linux.LANDLOCK_MAX_NUM_LAYERS {
		t.Errorf("NumLayers = %d, want %d", got, linux.LANDLOCK_MAX_NUM_LAYERS)
	}

	if _, err := d.Merge(rulesetWith(read, map[uint64]uint64{inoRoot: read})); !linuxerr.Equals(linuxerr.E2BIG, err) {
		t.Errorf("Merge beyond LANDLOCK_MAX_NUM_LAYERS = %v, want E2BIG", err)
	}
	// The over-limit merge must leave the original domain untouched.
	if got := d.NumLayers(); got != linux.LANDLOCK_MAX_NUM_LAYERS {
		t.Errorf("NumLayers after failed merge = %d, want %d", got, linux.LANDLOCK_MAX_NUM_LAYERS)
	}
}

// TestLandlockScopeLE verifies the domain ordering that Landlock's ptrace
// restriction is built on: a tracer may only trace a target confined by the
// tracer's own domain or a descendant of it.
//
// Matches Linux [security/landlock/task.c]:domain_scope_le()
func TestLandlockScopeLE(t *testing.T) {
	const read = linux.LANDLOCK_ACCESS_FS_READ_FILE

	// d1 is enforced first; d2 stacks another layer on top of it, so d2 is a
	// descendant of d1. other is an unrelated domain enforced from scratch.
	d1 := domainWith(t, rulesetWith(read, map[uint64]uint64{inoA: read}))
	d2, err := d1.Merge(rulesetWith(read, map[uint64]uint64{inoB: read}))
	if err != nil {
		t.Fatalf("Merge = %v, want nil", err)
	}
	other := domainWith(t, rulesetWith(read, map[uint64]uint64{inoA: read}))

	var none *LandlockDomain
	for _, test := range []struct {
		name           string
		tracer, tracee *LandlockDomain
		want           bool
	}{
		{"unsandboxed tracer, unsandboxed tracee", none, none, true},
		{"unsandboxed tracer, sandboxed tracee", none, d1, true},
		{"sandboxed tracer, unsandboxed tracee", d1, none, false},
		{"same domain", d1, d1, true},
		{"ancestor tracing descendant", d1, d2, true},
		{"descendant tracing ancestor", d2, d1, false},
		{"unrelated domains", d1, other, false},
		{"unrelated domains, reversed", other, d1, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.tracer.ScopeLE(test.tracee); got != test.want {
				t.Errorf("ScopeLE = %v, want %v", got, test.want)
			}
			// auth.LandlockCanPtrace is what kernel.Task.CanTrace calls, and it
			// must agree, including when a domain arrives as a nil interface
			// rather than a typed nil pointer.
			var tracer, tracee auth.LandlockDomain
			if test.tracer != nil {
				tracer = test.tracer
			}
			if test.tracee != nil {
				tracee = test.tracee
			}
			if got := auth.LandlockCanPtrace(tracer, tracee); got != test.want {
				t.Errorf("auth.LandlockCanPtrace = %v, want %v", got, test.want)
			}
		})
	}
}

// newLandlockTestFile returns a Dentry with a LandlockObjectSlot, on a
// Filesystem constructed directly rather than through Init.
func newLandlockTestFile() (*Filesystem, *dentryTestDentry) {
	return &Filesystem{vfs: &VirtualFilesystem{}}, newDentryTestDentry()
}

// getObject returns d's Landlock object with a new reference, failing t on
// error.
func getObject(t *testing.T, fs *Filesystem, d *dentryTestDentry) *LandlockObject {
	t.Helper()
	o, err := d.slot.GetObject(fs, d.dentry())
	if err != nil {
		t.Fatalf("GetObject = %v, want nil", err)
	}
	return o
}

// TestLandlockObjectLifecycle verifies that a file's Landlock object is shared
// by every rule for the file, holds a reference on the file's Dentry for as
// long as a ruleset or domain refers to it, and is replaced rather than
// revived once the last of them is gone, so that rules left holding the old
// Landlock object can never match again.
//
// Matches Linux [security/landlock/fs.c]:get_inode_object() and
// release_inode().
func TestLandlockObjectLifecycle(t *testing.T) {
	const read = linux.LANDLOCK_ACCESS_FS_READ_FILE
	ctx := context.Background()
	fs, d := newLandlockTestFile()

	o := getObject(t, fs, d)
	if got := d.refs.Load(); got != 2 {
		t.Fatalf("Dentry refs after creating its object = %d, want 2", got)
	}
	if again := getObject(t, fs, d); again != o {
		t.Fatalf("GetObject returned %p, then %p: a file must have one object", o, again)
	}
	if got := o.refs.Load(); got != 2 {
		t.Fatalf("object refs = %d, want 2", got)
	}
	if got := d.refs.Load(); got != 2 {
		t.Fatalf("Dentry refs after reusing its object = %d, want 2", got)
	}
	// Drop the second GetObject's reference.
	o.DecRef(ctx)

	// Two rules for the file in one ruleset share the ruleset's reference.
	rs := NewLandlockRuleset(read)
	rs.InsertRule(ctx, o, read)
	rs.InsertRule(ctx, getObject(t, fs, d), read)
	if got := o.refs.Load(); got != 1 {
		t.Fatalf("object refs with one ruleset holding it = %d, want 1", got)
	}

	domain, err := (*LandlockDomain)(nil).Merge(rs)
	if err != nil {
		t.Fatalf("Merge = %v, want nil", err)
	}
	stacked, err := domain.Merge(NewLandlockRuleset(read))
	if err != nil {
		t.Fatalf("Merge = %v, want nil", err)
	}
	// The ruleset's file description is closed, and the task holding the
	// first domain stacks the second on top of it.
	rs.release(ctx)
	domain.DecRef(ctx)
	if d.slot.Object() != o || d.refs.Load() != 2 {
		t.Fatalf("object released while a domain still refers to it")
	}
	masks := stacked.newLayerMasks(read)
	masks.unmask(d.vfsd.landlockObject())
	if masks.remaining[0] != 0 {
		t.Errorf("the rule of the first layer does not match its file")
	}

	stacked.DecRef(ctx)
	if !d.slot.IsEmpty() {
		t.Errorf("slot still holds the object after the last domain was released")
	}
	if got := d.refs.Load(); got != 1 {
		t.Errorf("Dentry refs after its object was released = %d, want 1", got)
	}
	if len(fs.landlockObjects) != 0 {
		t.Errorf("released object is still registered on its Filesystem")
	}

	// A new rule for the file gets a new Landlock object, which a rule holding
	// the released one does not match.
	o2 := getObject(t, fs, d)
	if o2 == o {
		t.Errorf("released object was revived")
	}
	o2.DecRef(ctx)
}

// TestLandlockObjectReplacedWhileReleasing verifies that a Landlock object
// whose last reference is being dropped is replaced rather than revived by a
// concurrent lookup, and that the release it was waiting on then leaves the
// replacement alone, as in Linux, where get_inode_object()'s
// refcount_inc_not_zero() fails against a Landlock object that release_inode()
// has yet to clear.
func TestLandlockObjectReplacedWhileReleasing(t *testing.T) {
	ctx := context.Background()
	fs, d := newLandlockTestFile()

	o := getObject(t, fs, d)
	// Drop the last reference without releasing, as a DecRef racing with
	// the lookup below would before it reached release().
	o.refs.Store(0)
	o2 := getObject(t, fs, d)
	if o2 == o {
		t.Fatalf("GetObject revived an object with no references")
	}
	o.release(ctx)
	if d.slot.Object() != o2 {
		t.Errorf("releasing the replaced object emptied the slot of its replacement")
	}
	if got := d.refs.Load(); got != 2 {
		t.Errorf("Dentry refs = %d, want 2: one held by the replacement", got)
	}
	o2.DecRef(ctx)
	if got := d.refs.Load(); got != 1 {
		t.Errorf("Dentry refs after releasing the replacement = %d, want 1", got)
	}
}

// TestLandlockObjectDetach verifies that destroying a Filesystem detaches the
// Landlock objects of its files, dropping their Dentry references while the
// rules referring to them remain, and that the rules' later release does not
// drop the references a second time.
//
// Matches Linux [security/landlock/fs.c]:hook_sb_delete()
func TestLandlockObjectDetach(t *testing.T) {
	const read = linux.LANDLOCK_ACCESS_FS_READ_FILE
	ctx := context.Background()
	fs, d := newLandlockTestFile()
	_, dead := newLandlockTestFile()

	rs := NewLandlockRuleset(read)
	rs.InsertRule(ctx, getObject(t, fs, d), read)
	rs.InsertRule(ctx, getObject(t, fs, dead), read)
	dead.vfsd.dead = true

	fs.detachDeadLandlockObjects(ctx)
	if !dead.slot.IsEmpty() || dead.refs.Load() != 1 {
		t.Errorf("object of a deleted file was not detached")
	}
	if d.slot.IsEmpty() || d.refs.Load() != 2 {
		t.Errorf("object of a live file was detached")
	}

	fs.detachLandlockObjects(ctx, nil)
	if !d.slot.IsEmpty() || d.refs.Load() != 1 {
		t.Errorf("object was not detached when its Filesystem was destroyed")
	}
	rs.release(ctx)
	if d.refs.Load() != 1 || dead.refs.Load() != 1 {
		t.Errorf("releasing a detached object dropped its Dentry reference again")
	}
}

// TestLandlockMergeKeepsParentRules verifies that stacking a layer with a rule
// for a file the parent already has a rule for leaves the parent's rule alone,
// even when two domains are derived from the same parent.
func TestLandlockMergeKeepsParentRules(t *testing.T) {
	const read, write = linux.LANDLOCK_ACCESS_FS_READ_FILE, linux.LANDLOCK_ACCESS_FS_WRITE_FILE
	parent := domainWith(t, rulesetWith(read|write, map[uint64]uint64{inoA: read | write}))
	d1, err := parent.Merge(rulesetWith(read|write, map[uint64]uint64{inoA: read}))
	if err != nil {
		t.Fatalf("Merge = %v, want nil", err)
	}
	d2, err := parent.Merge(rulesetWith(read|write, map[uint64]uint64{inoA: write}))
	if err != nil {
		t.Fatalf("Merge = %v, want nil", err)
	}
	a := testObjects[inoA]
	if got := len(parent.rules[a]); got != 1 {
		t.Errorf("parent has %d layers of rules for A, want 1", got)
	}
	if err := checkAncestry(d1, ids(inoA), read); err != nil {
		t.Errorf("d1 read = %v, want nil", err)
	}
	if err := checkAncestry(d1, ids(inoA), write); !linuxerr.Equals(linuxerr.EACCES, err) {
		t.Errorf("d1 write = %v, want EACCES", err)
	}
	if err := checkAncestry(d2, ids(inoA), write); err != nil {
		t.Errorf("d2 write = %v, want nil", err)
	}
	if err := checkAncestry(d2, ids(inoA), read); !linuxerr.Equals(linuxerr.EACCES, err) {
		t.Errorf("d2 read = %v, want EACCES", err)
	}
}
