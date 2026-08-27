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

package cgroup2fs

import (
	"testing"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// assertFreezeCreditState fails the test if node's nrChildrenWithCredits
// isn't exactly wantChildrenWithCredits, or if its frozenLocked() doesn't
// match wantFrozen. The exact count matters, not just non-negativity: a
// transient over-count that's later cancelled by a matching under-count
// leaves the final value correct while still passing through a wrong
// intermediate value, which a frozenLocked()-only check can't see (both
// the correct and the miscounted value are "> 0", hence equally
// "unsettled").
// +checklocksread:node.fs.tasksMu
func assertFreezeCreditState(t *testing.T, step, name string, node *cgroup, wantChildrenWithCredits int64, wantFrozen bool) {
	t.Helper()
	if got := node.nrChildrenWithCredits.Load(); got != wantChildrenWithCredits {
		t.Fatalf("%s: %s.nrChildrenWithCredits = %d, want %d", step, name, got, wantChildrenWithCredits)
	}
	if got := node.frozenLocked(); got != wantFrozen {
		t.Errorf("%s: %s.frozenLocked() = %v, want %v", step, name, got, wantFrozen)
	}
}

// runFreezeThawCycle exercises applyFreezeCreditDeltaLocked against a
// W -> A -> B tree the same way a real freeze/thaw of that hierarchy would,
// asserting nrChildrenWithCredits and frozenLocked() at each step. It's the
// core of TestFreezeCreditAccountingAccountsForGrandchildren, extracted so
// the test can run it twice and confirm the second cycle behaves
// identically to the first (i.e. nothing was left corrupted by the first).
// +checklocksread:w.fs.tasksMu
// +checklocksread:a.fs.tasksMu
// +checklocksread:b.fs.tasksMu
func runFreezeThawCycle(t *testing.T, ctx context.Context, cycle string, w, a, b *cgroup) {
	t.Helper()

	// B's task gets its credit first (mirrors b_pid entering B).
	applyFreezeCreditDeltaLocked(ctx, kernel.FreezeCreditIssue, b, false)
	assertFreezeCreditState(t, cycle+": after B issue", "b", b, 0, false)
	assertFreezeCreditState(t, cycle+": after B issue", "a", a, 1, false)
	assertFreezeCreditState(t, cycle+": after B issue", "w", w, 1, false)

	// A's own task also gets a credit (mirrors a_pid entering A). A's own
	// nrFreezeCredits (not asserted directly here, but exercised via
	// applyFreezeCreditDeltaLocked) crosses 0->1, which -- absent the
	// nrChildrenWithCredits guard in propagateHasCreditsLocked -- would
	// wrongly walk up and bump w.nrChildrenWithCredits to 2, even though
	// w's aggregate hasFreezeCredits() didn't actually newly change (B's
	// credit already made it true). w must stay at exactly 1.
	applyFreezeCreditDeltaLocked(ctx, kernel.FreezeCreditIssue, a, false)
	assertFreezeCreditState(t, cycle+": after A issue", "a", a, 1, false)
	assertFreezeCreditState(t, cycle+": after A issue", "w", w, 1, false)

	// The regression this test exists for: A's own task parks -- while B's
	// credit is still outstanding. A must stay unsettled because of B, not
	// because of its own (now-resolved) credit; the original bug's
	// ancestor walk only checked the latter, wrongly propagating
	// "settled" past A and up to W here.
	applyFreezeCreditDeltaLocked(ctx, kernel.FreezeCreditRetract, a, false)
	assertFreezeCreditState(t, cycle+": after A retract (B still owes)", "a", a, 1, false)
	assertFreezeCreditState(t, cycle+": after A retract (B still owes)", "w", w, 1, false)

	// B's task also parks: only now should the whole tree settle.
	applyFreezeCreditDeltaLocked(ctx, kernel.FreezeCreditRetract, b, false)
	assertFreezeCreditState(t, cycle+": after B retract", "b", b, 0, true)
	assertFreezeCreditState(t, cycle+": after B retract", "a", a, 0, true)
	assertFreezeCreditState(t, cycle+": after B retract", "w", w, 0, true)
}

// TestFreezeCreditAccountingAccountsForGrandchildren regresses a counting
// bug in updatePendingFreeze: an ancestor walk propagated "settled" past a
// cgroup whose own task had parked, without checking whether a
// grandchild's subtree (nrChildrenWithCredits) was still unsettled -- once
// the grandchild settled too, the ancestor's counter went permanently
// negative.
//
// This calls applyFreezeCreditDeltaLocked directly against a bare
// three-node *cgroup tree (no VFS, no *kernel.Task, no scheduling) to
// prove the invariant deterministically -- a syscall-level test can't
// reliably force this ordering (see cgroup2.cc's
// FreezeThawPropagatesThroughGrandchildTree for why).
//
// notify is false throughout: it only gates eventFile.Notify (see
// propagateHasCreditsLocked), and this test has no eventsFile -- it
// asserts on the counters and frozenLocked() directly instead.
func TestFreezeCreditAccountingAccountsForGrandchildren(t *testing.T) {
	ctx := context.Background()

	fs := &filesystem{}
	w := &cgroup{fs: fs}
	a := &cgroup{fs: fs, parent: w}
	b := &cgroup{fs: fs, parent: a}
	w.freezeRequested = true

	fs.tasksMu.Lock()
	defer fs.tasksMu.Unlock()

	// w.fs, a.fs, and b.fs are all fs (locked above): checklocks can't see
	// through the struct-literal construction to prove that alias, the
	// same way it can't for a curr/node loop variable walking c.parent
	// elsewhere in this package (e.g. propagateHasCreditsLocked's own
	// +checklocksforce uses for exactly this reason).
	runFreezeThawCycle(t, ctx, "cycle 1", w, a, b) // +checklocksforce: w.fs == a.fs == b.fs == fs, locked above

	// Thaw (retract both credits back out isn't needed: the tree is
	// already fully settled/credit-free after cycle 1) and run the exact
	// same cycle again. If cycle 1's settle had left
	// nrChildrenWithCredits corrupted (e.g. driven negative), cycle 2
	// would no longer behave identically -- it would either fail the
	// negative-counter check immediately or reach the wrong frozenLocked()
	// state at some step.
	runFreezeThawCycle(t, ctx, "cycle 2", w, a, b) // +checklocksforce: w.fs == a.fs == b.fs == fs, locked above
}
