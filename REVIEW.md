# gVisor Code Review Guide

This document defines the review principles, code review protocol, verification gates, risk tiers, and security review standards for pull requests in [`google/gvisor`](https://github.com/google/gvisor).

gVisor is an application kernel written in Go that implements a substantial portion of the Linux system call surface in user space. Because it forms a security boundary between untrusted sandboxed workloads and the host kernel, reviews prioritize **security, correctness, concurrency safety, and Linux compatibility**.

---

## 1. Core Principles

1. **Go deep first:** Read the surrounding subsystem context, trace lock lifecycles and error paths end-to-end, compare behavior against the Linux kernel and relevant RFCs, and report only findings backed by concrete code, trace, or test evidence.
2. **Calibrated skepticism:** When a change is small, coherent, and correct, say so plainly and approve. Never invent hypothetical problems to appear thorough. Conversely, request changes whenever there is a real correctness bug, Linux or RFC incompatibility, security regression, concurrency hazard, missing required test, or build breakage.
3. **Prefer structural enforcement over prose:** When an invariant can be enforced by the type system, a static analyzer (`+checklocks`, `+checkescape`, `nogo`), or a test, require the structural check rather than a prose comment.
4. **Zero noise on settled changes:** Check current PR state and existing review threads before commenting so reviews never duplicate already-resolved feedback.

### Scope, Priority & Tone Guardrails

1. **Direct, Constructive Technical Phrasing:**
   - State concretely what the code does, the 1-sentence consequence when non-obvious, and the exact deletion, split, or replacement.
2. **1–3 Sentence Inline Comment Budget:**
   - Keep inline comments to 1–3 sentences anchored to an exact `file:line` range on the added/modified (`+`) side of the diff (or at the PR level for whole-change scope, splitting, and description findings).
   - Include the concrete fix inline. Avoid filler praise (`"Great PR!"`), moralizing, or meta-commentary.
3. **Strict Diff Confinement & Linter Boundary:**
   - Audit only lines added or modified (`+`) in the PR and their direct behavioral impact on callers and state. Do not flag pre-existing comments, TODOs, or style issues on untouched context lines.
   - Defer formatting, import ordering, and mechanical lint to automated formatters and repository linters (`gofmt`, `goimports`, `clang-format`, `clang-tidy`, `buildifier`, `gazelle`, `nogo`).
4. **Structural Defects Before Nits & Zero-Noise Floor:**
   - Evaluate architectural bloat, opaque control flow, boundary bugs, swallowed errors, concurrency hazards, and vacuous tests before comment or prose nits.
   - Functionally correct code that forces readers to trace fallthrough state across nested branches is a `Minor` maintainability defect, not a stylistic nit.
   - Never polish comments or naming on code that another finding recommends deleting.
   - If a PR has zero verified findings (or only a single trivial stylistic nit with no behavioral or structural defect), approve cleanly without nit comments.

---

## 2. Code Review Protocol

Every PR goes through three independent reviews followed by the **Three-Gate Verification Filter** before a verdict is chosen. Each review should be conducted by an independent sub-agent managed by a coordinator agent. The coordinator agent should provide only the context necessary for each sub-agent to perform its assigned review. In addition to the three code reviews described below, the coordinator agent should also spawn a fourth independent review sub-agent that looks for any issues not explicitly mentioned in this document.

The coordinator agent is responsible for collecting and synthesizing sub-agent findings into a final report. It should push back on sub-agent findings if they need refinement, lack clarity, are incorrect, or conflict with other sub-agent findings.

### Review 1: Architecture, YAGNI, Naming, Comments & Description Grounding

- **PR Description & Commit Message Grounding:**
  - Verify that both the PR description and commit message accurately match the diff and call out any secondary behavior changes or bundled bug fixes.
  - When a PR fixes a Linux compatibility gap, check for an appropriate compatibility classification and rationale where applicable (see `AGENTS.md`).
  - If the PR body contains essential context while the commit message body is empty, ask the author to include that context in the commit message (see `CONTRIBUTING.md`).
  - **Ungrounded Safety or Scale Claims (`Minor`):** Flag claims such as `"completely thread-safe"`, `"guaranteed non-nil"`, or `"bounded upstream"` in descriptions or comments when locks, types, or callers do not actually enforce that invariant, or when stale text from temporary debugging scaffolding remains.
  - **Diff Recitation Without Motivation (`Minor`):** Flag descriptions that mechanically list modified files and functions without stating the problem or root cause being solved (exempting purely mechanical renames, generated code updates, or dependency bumps).
  - **Filler Openers & Hype Prose (`Nit`):** Avoid meta-intros (`"In this PR, we implement..."`) instead of an imperative summary line, marketing buzzwords (`"seamlessly"`, `"robust and scalable"`), or decorative emoji chains.
  - *Example:*
    > The PR description lists each modified file without explaining what bug or requirement motivated the change. Replace the file list with 1–2 sentences stating the root cause and why this approach was chosen.

- **Size & Atomic Sequencing:**
  - For PRs over **500 lines**, look for natural seams to split the change into smaller, independently verifiable PRs (for example, mechanical refactoring or plumbing first, behavior change and tests second).
  - Do not split a focused bug fix from its regression test when they belong together.

- **Architecture, YAGNI & Control-Flow Readability:**
  - Check for **Split Ownership** (multiple components mutating or caching the same state without a single authoritative owner), **Duplicate Mechanisms** for the same task, **Hand-Synced Lists**, and dead struct fields, unread parameters, or obsolete exported symbols left behind by the change.
  - **Single-Implementation Abstractions (`Minor`):** Introducing an interface, factory, or pass-through wrapper type/function with only one concrete implementation and no cross-package boundary or external-I/O test seam requirement.
  - **Speculative Knobs & Fallbacks (`Minor`):** Adding unrequested CLI flags, configuration options, or fallback branches for hypothetical contingencies.
  - **Default-Option Caller Dodging (`Minor`):** Adding default parameter values or nil-defaulting option fields to internal functions, methods, or constructors solely to avoid updating in-repo callers, hiding behavioral choices that call sites should pass explicitly (verify caller fan-out across the repository).
  - **Wheel Reinvention & Excessive Glue (`Minor`):** Re-implementing retry loops, parsers, or synchronization helpers already provided by the Go standard library (`slices`, `maps`, `errors`, `filepath`) or existing gVisor packages (`pkg/sync`, `pkg/cleanup`, `pkg/usermem`, `pkg/safemem`, `pkg/buffer`), while respecting `CONTRIBUTING.md` dependency restrictions on `core` and `runsc`.
  - **Branching Mazes & Fallthrough Error Paths (`Minor`):** Nesting positive checks (`if err == nil`, `if ok`) whose failure paths fall through to a distant trailing error return instead of using flat early guard returns where each precondition fails closed at the check site.
  - **Dense Compound Conditionals (`Minor`):** Packing side-effecting initializers with multi-clause predicates (`if x := ...; cond1 && cond2` when side effects obscure failure paths) or nested ternaries at the expense of top-to-bottom readability.
  - *Examples:*
    > `CacheFetcher` and its pass-through wrapper have only one concrete implementation and no cross-package boundary. Delete the interface and wrapper and call `MemoryCache` directly.

    > Positive `err == nil` checks are nested three levels deep and rely on fallthrough to a trailing error return, making it hard to verify every branch fails closed. Invert the conditions into early guard returns at each check site.

- **Naming, Comments & Timeless Documentation:**
  - **Delta-Relative or Session-Coupled Naming (`Minor`):** Naming functions, types, variables, parameters, or tests after an iteration or diff delta (`NewParser`, `UpdatedConfig`, `validateFixed`, `OptionBHandler`, `TestBugFix`, `TestEdgeCase2`) rather than their timeless domain role, invariant, or behavior under test (exempting genuine versioned protocols or schemas).
  - **Contextless Comments (`Minor`):** Writing comments that only make sense relative to prior review rounds or rejected approaches (`// Copy map here so we don't hit the issue above`, `// Keep original behavior for Case B`) instead of stating the self-contained invariant directly, or referencing callers (`"Used by..."`) instead of describing what the symbol itself guarantees.
  - **Step Banners & Syntax Narration (`Nit`):** Numbered banners (`// Step 1: Validate input`) or comments that restate the next line of code (`// Increment counter` above `count++`).
  - **Signature-Repeating Docstrings (`Nit`):** Multi-line comments on trivial internal helpers that repeat parameter and return names without documenting invariants or error semantics.
  - **Unowned TODOs & Historical Drift (`Nit`):** Bare `// TODO: fix` comments without an issue link or owner (`TODO(gvisor.dev/issue/12345):`), or transient migration phrasing (`"Recently migrated from X to Y"`, `"Previously gVisor did X"`) in documentation and comments instead of timeless steady-state behavior.
  - **The Comment Keep-List:** Keep comments focused on:
    1. License headers and build/analyzer directives (`// +checklocks:...`, `// +checkescape`, `// +stateify savable`, `//go:nosplit`).
    2. Exported API contracts and non-checkable preconditions/postconditions.
    3. Citations to analogous Linux kernel functions (`fs/locks.c:posix_lock_inode()`) or RFC sections that explain external behavior gVisor matches.
    4. Non-obvious constraints imposed by hardware, the host kernel, seccomp filters, or external tooling.
    When a prose comment states a lock precondition (`// mu must be locked`), replace the prose with `+checklocks:mu` rather than keeping both.

---

### Review 2: Correctness, Error Integrity, Linux Parity & Test Proportionality

- **Linux Kernel ABI & RFC Equivalence:**
  - Behavior visible to sandboxed applications—syscall semantics, `errno` values, ABI struct layouts, signal delivery, network wire behavior, and `/proc` or `/sys` contents—must match Linux.
  - Locate and verify the analogous Linux kernel behavior (for example, `fs/locks.c:posix_lock_inode()`, `net/ipv4/tcp_input.c:tcp_tsopt_ecr_before()`, `fs/signalfd.c:do_signalfd4()`, `fs/overlayfs/dir.c:ovl_cleanup_and_whiteout()`) and relevant RFCs (for example, RFC 7323, RFC 8985).
  - Encourage citing the analogous Linux function or RFC section in a brief comment when implementing or fixing subtle compatibility behavior.
  - Check representation differences between gVisor and Linux (for example, whether an option flag can be `true` when its associated value is `0`, or where a helper runs relative to sequence-number or permission checks).

- **Root-Cause Fixes & Error-Path Integrity:**
  - Verify the change fixes the underlying root cause rather than masking a symptom.
  - Trace every early return, error branch, and retry path to confirm partial registrations, reference counts (`IncRef`/`DecRef`), reservations, and state mutations are rolled back cleanly (using `pkg/cleanup` where multi-step teardown is needed).
  - **Silent Error Swallowing & Reachable Panics (`Blocking`):** Flag discarded errors (`_ = err`, `_ = fn()`), swallowed exceptions, fabricated fallback return values on I/O or state failures, and any `panic()` reachable from untrusted inputs or recoverable runtime errors.
  - **Ad-Hoc Structured Data Parsing (`Blocking`):** Flag regexes or fragile substring slicing used in production code to parse structured formats (JSON, YAML, Protobuf, ELF headers, structured `/proc` tables) instead of proper parsers.
  - **Unjustified Analyzer or Type Suppressions (`Minor`):** Flag `//nolint`, `// NOLINT`, `// +checklocksforce`, `// +checklocksignore`, or `unsafe` casts added without narrowing the scope, naming the `_unsafe.go` file per `CONTRIBUTING.md`, and documenting why the safety invariant holds.
  - **Redundant Internal Defensive Checks (`Minor`):** Flag impossible-state checks on trusted internal invariants (such as `s != nil && len(s) > 0` in Go or duplicate nil checks on non-optional internal state), while **preserving all validation at untrusted and external boundaries** (see Gate 1 below).
  - **Errors Used for Routine Control Flow (`Minor`):** Flag internal helpers that allocate/return `error` for expected optional lookups where callers inspect `err == nil` and discard the error instead of returning `(val, ok)`.

- **Blast Radius & Verification Depth:**
  - Identify **the key invariant the change relies on for safety** and verify it in the codebase rather than assuming it holds:
    1. *Asserted in prose* (insufficient) → 2. *Verified at `file:line`* → 3. *Traced across all callers and states* → 4. *Verified via build and tests* → 5. *Proved end-to-end in a sandbox run*.
  - Check cross-cutting surfaces that plain symbol search misses:
    - **Checkpoint/Restore (`+stateify savable`):** Does adding, removing, or reinterpreting a field affect saved state, wire compatibility, `state:"nosave"` rebuilding, or `afterLoad` hooks?
    - **Build, `nogo` & Multi-Platform Targets:** Are `BUILD` targets (`//tools:defs.bzl` wrappers), `go.mod`/`WORKSPACE` dependencies (`gazelle`), `amd64`/`arm64` platform splits, `pagesize_64k` builds, and `core`/`runsc` allowed-dependency rules (`CONTRIBUTING.md`) preserved?
    - **Merge Cleanliness:** Does the branch conflict semantically with recent `master` changes in the same subsystem?

- **Test Integrity, Mocking & Proportionality:**
  - **Linux-observable behavior:** Require syscall tests in `test/syscalls/linux` (GoogleTest C++) that run identically against both native Linux (`native`) and gVisor (`runsc_*`), using syscall matchers (`SyscallSucceeds()`, `SyscallSucceedsWithValue(...)`, `SyscallFailsWithErrno(...)`). Do not accept Go unit tests as a substitute for application-observable syscall, filesystem, ioctl, socket, `/proc`, or `/sys` behavior. For wire-level network behavior that socket syscalls cannot deterministically synthesize, use `test/packetimpact` or `test/packetdrill`.
  - **Undefined behavior on native Linux:** When a test exercises behavior that Linux leaves undefined (such as racing direct host mutations against a mounted overlay layer), verify stability on native Linux or gate gVisor-specific assertions appropriately (`IsRunningOnGvisor()`).
  - **gVisor-internal & runtime features:** Go unit tests are appropriate for self-contained internal data structures and allocators (`pkg/sentry/pgalloc`, `pkg/segment`, `pkg/buffer`); for `runsc` CLI, container lifecycle, checkpoint/restore, and gofer integration, prefer real container integration tests (`runsc/container`) over mock-heavy unit tests.
  - **Tautological or Vacuous Tests (`Blocking`):** Flag tests that assert stubbed mock return values, verify mock call counts without checking observable state/output, fail to exercise each conjunct of a new condition, or continue passing if the production fix is reverted.
  - **Excessive Mocking (`Minor`):** Flag mock-heavy test harnesses (`>= 10:1` mock setup to assertions) where real value types, in-memory fakes, or existing gVisor test utilities can be used directly.
  - **Sleep-Based Synchronization (`Minor`):** Flag hardcoded `time.Sleep()` / `sleep()` delays used to coordinate concurrent test goroutines or threads instead of channels, barriers, wait groups, fake clocks, or bounded condition polling.
  - **Disproportionate Test Scaffolding (`Minor`):** Prefer adding a case to an existing table-driven or parameterized test over duplicating a 30+ line fixture for a 1–2 line guard, and do not ask authors to write dedicated unit tests for trivial guards.

---

### Review 3: Performance, Benchmarking & Concurrency

- **Performance & Benchmarking:**
  - Pay special attention to performance-sensitive paths:
    - Syscall hot path (`pkg/sentry/kernel`, `pkg/sentry/syscalls/linux`, `pkg/usermem`, `pkg/safemem`, `pkg/safecopy`, `pkg/marshal`)
    - Platform & ring0 (`pkg/sentry/platform`, `pkg/ring0`)
    - Sandbox startup (`runsc/boot`, `runsc/container`, `runsc/sandbox`) and Go `init()` functions (avoid `init()`, especially syscalls or large allocations at startup)
    - Checkpoint/restore & serialization (`pkg/state`, `pkg/sentry/state`)
    - Netstack (`pkg/tcpip`), VFS & filesystems (`pkg/sentry/vfs`, `pkg/sentry/fsimpl`), memory management (`pkg/sentry/mm`, `pkg/sentry/pgalloc`), and gofer IPC (`pkg/lisafs`, `runsc/fsgofer`)
  - **Benchmark justification for performance claims:** Changes motivated by performance—or touching hot paths with non-obvious performance tradeoffs—must include statistically significant before/after `benchstat` results (or add a benchmark if none covers the path) and must not regress unrelated workloads.
  - Audit hot paths for extra host syscalls, extra gofer RPC round trips, per-operation heap allocations (`// +checkescape`), un-presized slices/maps, unnecessary saved checkpoint state (`state:"nosave"`), lock contention, or sidecar binary size growth.
  - Watch test runtime under slower platforms (`ptrace`, `systrap`), flagging tests that run excessive iterations or threads when far fewer reproduce the issue.
  - Vet benchmark methodology and claims against **7 benchmark questions**:
    1. **What is the limiter?** Why wasn't the speedup larger—what bottleneck remains?
    2. **Are configurations matched?** Did before and after run with identical production-representative flags and platforms?
    3. **Does the delta match Amdahl's law?** Is the claimed improvement plausible given the fraction of runtime spent in the modified path?
    4. **Were errors excluded?** Did any fast path short-circuit on silent errors instead of completing real work?
    5. **Is it reproducible?** Were runs interleaved (`n >= 16` or `p < 0.01` in `benchstat`) with variance reported?
    6. **Does it matter end-to-end?** Does a microbenchmark win hold up on realistic syscall or container workloads?
    7. **Is the timed region accurate?** Are `b.StopTimer()` / `b.StartTimer()` placed so setup/teardown is excluded and the target operation actually executes inside the timed loop?

- **Concurrency, Lock Ordering & `checklocks`:**
  - Require `+checklocks` annotations (`// +checklocks:mu`, `// +checklocksread:mu`, `// +checklocksacquire:mu`, `// +checklocksrelease:mu`, `// +checklocksexclude:mu`) on mutex-protected fields and lock-assuming functions. Declare mutexes (`mu` or `xxxMu`, unexported) immediately above the fields they protect.
  - Favor small refactors that keep lock ownership visible to `checklocks` instead of reaching for `+checklocksforce` or `+checklocksignore`.
  - Trace the **lock acquisition hierarchy** across callers, callbacks, and `defer` statements to rule out deadlocks and races:
    - Confirm locks are released before external notifications, callbacks, or potentially blocking host I/O.
    - Check `defer` LIFO execution order whenever multiple unlock, cleanup, or unregister steps are stacked.
    - Check wait-queue registration ordering relative to state mutations so wakeups cannot be lost and closed channels cannot be sent to.
    - Whenever a mutex is temporarily unlocked across host I/O or zeroing/decommit operations, verify both (a) what pins the underlying FD or mapping against concurrent close/unmap, and (b) that in-memory state transitions *before* unlocking so racing callers cannot double-free or observe inconsistent state.

---

### Three-Gate Verification Filter (Mandatory Before Emitting Findings)

Every candidate finding from the reviews must pass all three gates; drop any candidate that fails a gate:

1. **Gate 1 — Diff & Boundary Evidence:** Confirm the finding cites an exact `file:line` on the `+` side of the diff (or is genuinely PR-wide). Drop any "redundant defensive check" candidate if the check guards an untrusted or external boundary (syscall arguments, `CopyIn`/application memory, network packets, checkpoint restore streams, OCI spec / CLI / config inputs, gofer RPC messages, or host FD I/O) or performs required resource cleanup.
2. **Gate 2 — Test Isolation Check:** Confirm any flagged mock or test double is genuinely vacuous or over-mocked rather than a necessary seam isolating external network access, host root/device capabilities, or non-deterministic host kernel behavior.
3. **Gate 3 — Codebase Precedent, Ownership & Split Independence:** Inspect sibling files and callers (`git grep`, surrounding package files) to confirm a flagged abstraction, naming choice, option struct, or helper genuinely violates local package conventions rather than matching established gVisor patterns (such as generated segment/list templates or staged interface migrations). Before recommending splitting a large PR, verify that each proposed slice compiles, passes tests, and preserves invariants independently without leaving dead code or broken callers.

---

## 3. Risk Tiers & Security Review

### Risk Tiers

| Tier | Scope | Examples | Review Depth |
| --- | --- | --- | --- |
| **Low** | Internal static-analysis annotations, documentation, comments, tests, benchmarks, build rules, or small internal-only fixes that do not alter Sentry security boundaries or application-visible Linux semantics. | `+checklocks` annotations, benchmark or test fixes, documentation updates, `BUILD` rule cleanups. | Full code review protocol and Three-Gate Filter; verify build, lint, and test coverage. |
| **Medium** | Standard Sentry, VFS, filesystem, memory management, netstack, checkpoint/restore, or `runsc` lifecycle changes affecting application-visible behavior or resource management. | Overlay whiteouts, `tmpfs`/`pgalloc` lifecycle, TCP recovery/timestamps, `epoll`/`signalfd`/`eventfd` semantics, `procfs`/`sysfs` behavior. | Full code review protocol **plus** a dedicated security pass against `SECURITY.md` and Linux parity / syscall test verification. |
| **High** | Changes touching sandbox isolation boundaries, seccomp filters, platform/ring0 interception, host device or filesystem passthrough, `unsafe` memory/serialization primitives, or major hot-path architectures. | Seccomp rules, `directfs`/`fsgofer` host path handling, `nvproxy` ioctl/device passthrough, `pkg/state` wire/graph decoding, `systrap`/`kvm` platform code. | Deep code review protocol **plus** an exhaustive threat-model and boundary audit against `SECURITY.md` (and benchmark evidence where hot paths are affected). |

### Security Review Protocol (`SECURITY.md`)

gVisor's primary security goal is protecting the host and peer sandboxes from untrusted workloads inside a sandbox. Every **Medium** and **High** risk PR requires an explicit security pass grounded in [`SECURITY.md`](SECURITY.md):

1. **Enumerate Untrusted Inputs & Attackers (`SECURITY.md` Prerequisites):**
   - Identify which attacker prerequisite applies (`Remote`, `SandboxUser`, `SandboxRoot`, `SandboxImage`, `SandboxSpec`, `RuntimeFlags`, `HostRoot`) and trace all untrusted inputs entering the modified code:
     - Syscall arguments, pointers, lengths, flags, and concurrently mutated user memory from sandboxed tasks.
     - Operations on user-mountable filesystems (`AllowUserMount: true`) or untrusted container image layers (`SandboxImage`).
     - Raw network frames, headers, and protocol options from `Remote` peers.
     - Checkpoint state streams, OCI specs/annotations, environment variables, and gofer/host file responses.
2. **Walk the `SECURITY.md` Impact Taxonomy (Most to Least Severe):**
   - **Beyond the sandbox boundary (CVE-eligible scope when reachable from `Remote`..`SandboxImage`):**
     - `Escape`: Arbitrary code execution on the host or breakout across Sentry + host namespace/seccomp/gofer layers.
     - `HostLeak`: Unauthorized reads of host files, file metadata, or host memory outside configured mounts.
     - `Exfil`: Unauthorized data transmission or host writes outside sandbox network/mount policy.
     - `Lateral`: Code execution or interference in another sandbox on the same host.
     - `HostDoS`: Host kernel panic or unattributed host resource exhaustion (host FD leaks, unbounded host memory/disk/CPU allocation).
     - `PeerDoS`: Crashing or denying service to other sandboxes (or crashing a sandbox remotely via `Remote` network traffic).
   - **Confined to a single sandbox (still blocking correctness/security bugs in code review):**
     - `InternalEsc`: Unprivileged `SandboxUser` escalating privileges or bypassing permission/namespace checks inside the sandbox.
     - `InternalRead`: Unauthorized cross-user or cross-namespace information disclosure inside the sandbox (such as leaking root-PID-namespace IDs into a child namespace).
     - `SelfDoS`: In-sandbox actions triggering a Sentry `panic()`, nil-pointer dereference, deadlock, unbounded Sentry allocation, or send on a closed channel.
     - `Integrity`: Silent data corruption relative to Linux semantics (such as silent integer truncation or lost filesystem/memory state).
3. **Mandatory Security Checklist:**
   - **Host syscalls & seccomp:** Does the PR add host syscalls, widen seccomp filters, or require new host capabilities?
   - **Host FD & mapping lifecycle:** Are host FDs validated, closed on every error path (`unix.Close`), and protected against use-after-close / FD-reuse races when locks are dropped?
   - **Path traversal & symlink safety:** Are host, gofer, and overlay operations anchored to validated directory FDs (`O_NOFOLLOW` / `openat`-style traversal) without following untrusted symlinks or `..` segments?
   - **Integer overflow & allocation bounds:** Are lengths, offsets, page round-ups (`PageRoundUp`), and counts checked for overflow before arithmetic or slice/buffer allocation from untrusted sizes?
   - **Sentry `panic()` audit:** Confirm no newly added `panic(...)` can be triggered by untrusted application syscalls, malformed packets, or racing operations inside the sandbox.

---

## 4. Follow-Up Reviews & Summary Formatting

### Re-Review & Follow-Up Verification
When reviewing an updated PR after prior feedback:
1. **Isolate the delta:** Compare the previously reviewed commit against the new PR head (`git range-diff` for rebased/amended branches, `git diff` for incremental commits) and read all author replies.
2. **Verify every prior finding:** Confirm each earlier review comment is either fixed in code, declined with a sound technical explanation, or still outstanding—never silently drop unresolved items.
3. **Check thread resolution accuracy:**
   - Flag as `Blocking` any review thread marked resolved or `"Done"` when the cited lines have no functional fix (for example, renaming a symbol while leaving the underlying bug intact).
   - When a comment asked a design or invariant question (*why* / *how*), expect a direct technical explanation (and an invariant comment or structural check in code where helpful) rather than a bare `"Done"`.
4. **Audit newly added code:** Run the code review protocol and Three-Gate Verification Filter on all new or modified lines introduced since the previous review.

### Review Output Structure
- **Top-level review summary:** Keep the top-level review body concise—either a brief approval note when clean, or at most ~5 numbered high-level points summarizing substantive findings without repeating PR-description feedback twice. For Medium and High-risk PRs, include a 1–4 sentence `**Security:**` summary noting the boundary/taxonomy assessment.
- **Inline comments:** Anchor every line-specific finding directly on the relevant `+` lines of the diff, ordered by severity (`Blocking` → `Minor` → `Nit`), observing the 1–3 sentence budget and concrete fix requirement in §1.
