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

// testFS stands in for the filesystem the files below live on. Tests construct
// it directly rather than through Init, which would need a VirtualFilesystem.
var testFS = &Filesystem{id: 1}

// id returns the identity of the file numbered ino, all of which are taken to
// be on one filesystem.
func id(ino uint64) InodeIdentity {
	return MakeInodeIdentity(testFS, ino)
}

// ids returns the identities of the files numbered inos.
func ids(inos ...uint64) []InodeIdentity {
	out := make([]InodeIdentity, 0, len(inos))
	for _, ino := range inos {
		out = append(out, id(ino))
	}
	return out
}

// rulesetWith returns a ruleset handling handled, with a rule for each file in
// rules granting the rights it maps to.
func rulesetWith(handled uint64, rules map[uint64]uint64) *LandlockRuleset {
	rs := NewLandlockRuleset(handled)
	for ino, access := range rules {
		rs.InsertRule(id(ino), access)
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
func checkAncestry(d *LandlockDomain, ancestry []InodeIdentity, accessRights uint64) error {
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
		ancestry []InodeIdentity
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
			name:     "an ancestor with no identity is skipped",
			layers:   []*LandlockRuleset{rulesetWith(read, map[uint64]uint64{inoA: read})},
			ancestry: []InodeIdentity{id(inoB), {}, id(inoA), id(inoRoot)},
			rights:   read,
			allowed:  true,
		},
		{
			// Failing closed is what makes an unnameable file safe: it can only
			// be reached if some nameable ancestor of it grants the rights.
			name:     "a file with no identity and no covering rule is denied",
			layers:   []*LandlockRuleset{rulesetWith(read, map[uint64]uint64{inoA: read})},
			ancestry: []InodeIdentity{{}},
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
	rs.InsertRule(id(inoA), read)
	rs.InsertRule(id(inoA), write)
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

	rs.InsertRule(id(inoB), read)

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

func TestLandlockOpenAccessRights(t *testing.T) {
	for _, test := range []struct {
		name  string
		opts  OpenOptions
		isDir bool
		want  uint64
	}{
		{
			name: "O_RDONLY requires read",
			opts: OpenOptions{Flags: linux.O_RDONLY},
			want: linux.LANDLOCK_ACCESS_FS_READ_FILE,
		},
		{
			name: "O_WRONLY requires write",
			opts: OpenOptions{Flags: linux.O_WRONLY},
			want: linux.LANDLOCK_ACCESS_FS_WRITE_FILE,
		},
		{
			// Linux derives the rights from f_mode, which has both bits set.
			name: "O_RDWR requires read and write",
			opts: OpenOptions{Flags: linux.O_RDWR},
			want: linux.LANDLOCK_ACCESS_FS_READ_FILE | linux.LANDLOCK_ACCESS_FS_WRITE_FILE,
		},
		{
			// execve(2) opens with O_RDONLY, so Linux requires the right to
			// read the file as well as the right to execute it.
			name: "exec requires execute and read",
			opts: OpenOptions{Flags: linux.O_RDONLY, FileExec: true},
			want: linux.LANDLOCK_ACCESS_FS_READ_FILE | linux.LANDLOCK_ACCESS_FS_EXECUTE,
		},
		{
			name:  "a directory requires read_dir",
			opts:  OpenOptions{Flags: linux.O_RDONLY | linux.O_DIRECTORY},
			isDir: true,
			want:  linux.LANDLOCK_ACCESS_FS_READ_DIR,
		},
		{
			// Landlock keys on the file type, not on O_DIRECTORY.
			name:  "a directory opened without O_DIRECTORY still requires read_dir",
			opts:  OpenOptions{Flags: linux.O_RDONLY},
			isDir: true,
			want:  linux.LANDLOCK_ACCESS_FS_READ_DIR,
		},
		{
			name: "unrelated flags do not change the rights",
			opts: OpenOptions{Flags: linux.O_WRONLY | linux.O_CREAT | linux.O_TRUNC | linux.O_APPEND},
			want: linux.LANDLOCK_ACCESS_FS_WRITE_FILE,
		},
		{
			// OPEN_FMODE() maps the fourth access mode to a file that is
			// neither readable nor writable, so no right is required.
			name: "the fourth access mode requires nothing",
			opts: OpenOptions{Flags: linux.O_ACCMODE},
			want: 0,
		},
		{
			name:  "the fourth access mode on a directory requires nothing",
			opts:  OpenOptions{Flags: linux.O_ACCMODE},
			isDir: true,
			want:  0,
		},
		{
			// The right to execute is still required on its own, since
			// __FMODE_EXEC lives outside the access mode.
			name: "the fourth access mode with exec requires execute",
			opts: OpenOptions{Flags: linux.O_ACCMODE, FileExec: true},
			want: linux.LANDLOCK_ACCESS_FS_EXECUTE,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			opts := test.opts
			if got := landlockOpenAccessRights(&opts, test.isDir); got != test.want {
				t.Errorf("landlockOpenAccessRights() = %#x, want %#x", got, test.want)
			}
		})
	}
}

func TestCheckLandlockMount(t *testing.T) {
	const read = linux.LANDLOCK_ACCESS_FS_READ_FILE

	var none *LandlockDomain
	if err := CheckLandlockMount(none); err != nil {
		t.Errorf("CheckLandlockMount(nil) = %v, want nil", err)
	}

	// Landlock has no right that grants a mount, so a domain denies it whatever
	// it handles and whatever rules it holds.
	d := domainWith(t, rulesetWith(read, map[uint64]uint64{inoRoot: read}))
	if err := CheckLandlockMount(d); !linuxerr.Equals(linuxerr.EPERM, err) {
		t.Errorf("CheckLandlockMount(domain) = %v, want EPERM", err)
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

// TestInodeIdentityIsScopedToFilesystem verifies that identities from two
// different filesystems never compare equal, even when both filesystems report
// the same inode number.
//
// Inode numbers only name files within their own filesystem, and nothing stops
// two filesystems from using the same ones — a gofer takes them from the host,
// while tmpfs counts from 1. A rule keyed on a file of one filesystem would
// otherwise match an unrelated file on another, granting access the domain
// never allowed. Scoping by Filesystem also covers destruction: Filesystem IDs,
// unlike device numbers, are never reused, so a rule keyed on a file of a
// destroyed filesystem can never match a file on a later one.
func TestInodeIdentityIsScopedToFilesystem(t *testing.T) {
	// Same inode number, different filesystems, as happens when a filesystem
	// is destroyed and another is created after it.
	const ino = 42
	destroyed := &Filesystem{id: 1}
	recycled := &Filesystem{id: 2}

	first := MakeInodeIdentity(destroyed, ino)
	second := MakeInodeIdentity(recycled, ino)
	if first == second {
		t.Errorf("identities on distinct filesystems compare equal: %+v", first)
	}

	// A rule naming the file on the destroyed filesystem must not grant access
	// to the file that inherited its inode number.
	const read = linux.LANDLOCK_ACCESS_FS_READ_FILE
	rs := NewLandlockRuleset(read)
	rs.InsertRule(first, read)
	d := domainWith(t, rs)

	masks := d.newLayerMasks(read)
	masks.unmask(second)
	if masks.allowed() {
		t.Error("a rule from a destroyed filesystem granted access to a file on the filesystem that reused its inode number")
	}

	// The rule must of course still match its own file.
	masks = d.newLayerMasks(read)
	masks.unmask(first)
	if !masks.allowed() {
		t.Error("rule did not match the file it names")
	}
}
