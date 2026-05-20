// Copyright 2025 The gVisor Authors.
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

package gcs

import (
	"context"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/cenkalti/backoff"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
	"gvisor.dev/gvisor/pkg/sync"
)

// composeMax is the maximum number of inputs to a GCS compose operation:
// https://cloud.google.com/storage/docs/composing-objects
const composeMax = 32

// ParallelWriter implements stateio.AsyncWriter for a GCS object using
// recursive parallel composite upload.
type ParallelWriter struct {
	// GCS documentation
	// (https://cloud.google.com/storage/docs/parallel-composite-uploads)
	// describes parallel composite upload as: "a file is divided into up to 32
	// chunks, the chunks are uploaded in parallel to temporary objects, the
	// final object is recreated using the temporary objects, and the temporary
	// objects are deleted." ParallelWriter differs from this description since
	// the data to be written is not entirely known when writing begins, making
	// it impossible to divide the data into any fixed number of chunks in
	// advance. Instead, ParallelWriter directs each write to a separate
	// temporary object, and composes temporary objects into larger temporary
	// objects as writing proceeds (since each composition takes at most 32
	// source objects, but source objects can themselves be composite objects).
	//
	// Concretely, ParallelWriter's behavior can be divided into two phases:
	// behavior before Finalize is called and behavior when Finalize is called.
	//
	// ---
	//
	// Before Finalize(): Each write creates a temporary object at "level 0".
	// When write completions have produced 32 contiguous objects at level 0, a
	// composer goroutine is started to compose those objects into a temporary
	// composite object at level 1. The composer goroutine performs composition
	// recursively: if a composition of 32 objects at level N-1 produces 1
	// object at level N, which causes there to be 32 contiguous objects at
	// level N, then it also composes those objects into 1 object at level N+1.
	//
	// As an example, consider the composition graph after 1057 writes:
	//
	// Level 0: 0-31 32-63 ... 992-1023 1024-1055 1056
	//           |     |          |         |
	// Level 1:  0-----1--...----31        32
	//                     |
	// Level 2:            0
	//
	// - Object 0 at level 1 will be produced when writes 0-31 complete. The
	// writer goroutine that completes the last of these writes is responsible
	// for starting a composer goroutine to compose object 0 at level 1.
	//
	// - Object 0 at level 2 will be produced when writes 0-1023 complete, and
	// their respective composite objects 0-31 at level 1 have been produced.
	// The composer goroutine that composes the last of these objects at level
	// 1 is also responsible for composing object 0 at level 2.
	//
	// - Object 1056 at level 0 is not yet connected to any other nodes, since
	// we never instantiate nodes representing compositions with only one
	// source object. (If we did, then the first write would instantiate a node
	// representing object 0 at level 0, which would instantiate a node
	// representing object 0 at level 1, which would instantiate a node
	// representing object 0 at level 2, and so on infinitely.) Note that this
	// prevents the composition graph during this phase from being a tree.
	//
	// - Object 32 at level 1 is not yet connected to any node at level 2, for
	// the same reason.
	//
	// This graph is stored as follows:
	// - ParallelWriter.levels[0].firstPart => object 1056 at level 0
	// - ParallelWriter.levels[1].firstPart => object 32 at level 1
	// - ParallelWriter.levels[2].firstPart => object 0 at level 2
	// - All other nodes in the graph are either leaves or recursively-full
	// branches and reachable from one of the above, e.g. object 0 at level 1
	// is levels[2].firstPart.parts[0].
	//
	// After a 1058th write, the composition graph becomes:
	//
	// Level 0: 0-31 32-63 ... 992-1023 1024-1055 1056-1057
	//           |     |          |         |         |
	// Level 1:  0-----1--...----31        32--------33
	//                     |                     |
	// Level 2:            0---------------------1
	//                                |
	// Level 3:                       0
	//
	// - Object 33 at level 1, object 1 at level 2, and object 0 at level 3
	// don't yet exist, since they don't have 32 source objects to compose.
	//
	// This graph is stored as follows:
	// - ParallelWriter.levels[0].parent => object 33 at level 1
	// - ParallelWriter.levels[1].parent => object 1 at level 2
	// - ParallelWriter.levels[2].parent => object 0 at level 3
	// - ParallelWriter.levels[3].firstPart => object 0 at level 3
	// - All other nodes in the graph are either leaves or recursively-full
	// branches and reachable from one of the above.
	//
	// ---
	//
	// During Finalize(): Finalize discards incomplete branches (those without
	// 32 source objects) produced during writing and builds a new composition
	// tree that composes all existing temporary objects, in order to minimize
	// the required number of compositions.
	//
	// As an example, suppose Finalize is called after 1058 writes as shown
	// above:
	//
	// - Object 0 at level 2 either will be concurrently produced by the
	// composition of objects 0-31 at level 1, or has already been produced.
	//
	// - Object 32 at level 1 either will be concurrently produced by the
	// composition of objects 1024-1055 at level 0, or has already been
	// produced.
	//
	// - Objects 1056 and 1057 at level 0 have been produced by completed
	// writes.
	//
	// - Objects 33 at level 1, object 1 at level 2, and object 0 at level 3
	// will never exist and are discarded.
	//
	// Thus, Finalize composes these 4 objects into the final object produced
	// by the ParallelWriter.
	//
	// The final composition tree is not stored in the ParallelWriter; thus,
	// see ParallelWriter.buildFinalCompositionTree() for further details on
	// the construction of the tree.

	stateio.NoRegisterClientFD

	maxWriteBytes           uint64
	maxRanges               int
	bucket                  *storage.BucketHandle
	obj                     *storage.ObjectHandle
	subs                    chan *composeLeaf
	cmps                    chan stateio.Completion
	writerCtx               context.Context
	cancelWritesAndComposes context.CancelCauseFunc
	deleterCtx              context.Context
	cancelDeleters          context.CancelFunc

	// tmpFmt is the format string used to produce temporary object names.
	tmpFmt string

	// tmpFmtPrefixLen is the number of bytes to strip from the front of temporary
	// object names to obtain part numbers only, used for logging.
	tmpFmtPrefixLen int

	// prevLeaves is the number of writes that have ever been enqueued.
	prevLeaves uint64

	// levels is the write composition graph.
	levels []composeLevel

	// workers counts the number of writer and deleter goroutines (which are
	// persistent for the life of the ParallelWriter).
	workers sync.WaitGroup

	// composes counts the number of composer goroutines (which are created as
	// necessary).
	//
	// ParallelWriter.Close() cancels writerCtx, then waits for composes to
	// become 0. This can't leak objects created by concurrently-created
	// composer goroutines because http.Transport.roundTrip() checks for
	// ctx.Done() before sending anything. However, concurrent calls to
	// sync.WaitGroup.Add/Wait when the WaitGroup value is 0 will panic. Thus,
	// use sync.Gate instead of sync.WaitGroup to count composer goroutines.
	composes sync.Gate

	// If composeErr is non-nil, it is the error returned by any failed
	// composition. composeErrOnce is used to assign composeErr at most once.
	composeErrOnce sync.Once
	composeErr     error

	// deletes counts the number of pending object deletions.
	deletes sync.WaitGroup

	// delete holds objects to be deleted.
	delete chan *storage.ObjectHandle
}

// composeNode represents an object created during parallel composite upload.
type composeNode struct {
	// obj is the object being created for this node. obj becomes immutable
	// when ready becomes true.
	obj *storage.ObjectHandle

	readyMu sync.Mutex

	// If parent is non-nil, it is the branch that obj will be composed into.
	//
	// +checklocks:readyMu
	parent *composeBranch

	// If ready is true, obj has been created.
	//
	// +checklocks:readyMu
	ready bool

	// impl is the containing composeLeaf or composeBranch. impl is immutable.
	impl any
}

func (node *composeNode) node() *composeNode {
	return node
}

// composeLeaf represents an object created during parallel composite upload by
// writing to it.
type composeLeaf struct {
	composeNode
	id  int
	src stateio.LocalClientRanges
}

// composeBranch represents an object created during parallel composite upload
// by composing other objects.
type composeBranch struct {
	composeNode

	// If mixed is false, parts consists of a contiguous range of parts in a
	// single level. If mixed is true, parts may originate from different
	// levels. This is only used for logging.
	mixed bool

	// Composition of the object represented by this branch should be initiated
	// when partsReady == partsMax. partsMax is immutable.
	partsMax uint32

	// partsReady is the number of nodes in parts with node.ready == true.
	partsReady atomicbitops.Uint32

	// partsLen is the number of valid nodes in parts.
	//
	// Invariant: partsLen > 1.
	partsLen uint32

	parts [composeMax]*composeNode
}

func appendNodeObjs(nodes []*composeNode, objs []*storage.ObjectHandle) []*storage.ObjectHandle {
	for _, node := range nodes {
		objs = append(objs, node.obj)
	}
	return objs
}

type composeLevel struct {
	// Invariant: At most one of firstPart and parent is non-nil.

	// If firstPart is non-nil, it is the first part at this level that has not
	// yet been scheduled for composition into a part at the next level.
	firstPart *composeNode

	// If parent is non-nil, it is the branch that new parts at this level
	// should be composed into.
	parent *composeBranch

	// prevParents is the number of times parent has transitioned from non-nil
	// to nil, and is used to name new parents.
	prevParents uint64
}

// NewParallelWriter returns a ParallelWriter that constructs the given GCS
// object.
func NewParallelWriter(ctx context.Context, bkt *storage.BucketHandle, obj *storage.ObjectHandle, maxWriteBytes uint64, maxRanges, maxParallel int) (*ParallelWriter, error) {
	writerCtx, writerCancel := context.WithCancelCause(ctx)
	deleterCtx, deleterCancel := context.WithCancel(ctx)
	w := &ParallelWriter{
		maxWriteBytes:           maxWriteBytes,
		maxRanges:               maxRanges,
		bucket:                  bkt,
		obj:                     obj,
		subs:                    make(chan *composeLeaf, maxParallel),
		cmps:                    make(chan stateio.Completion, maxParallel),
		writerCtx:               writerCtx,
		cancelWritesAndComposes: writerCancel,
		deleterCtx:              deleterCtx,
		cancelDeleters:          deleterCancel,
		delete:                  make(chan *storage.ObjectHandle, maxParallel*2 /* arbitrary */),
	}
	w.initTmpFmt()
	w.workers.Add(maxParallel)
	for range maxParallel {
		go w.writerMain(writerCtx)
	}
	const numDeleters = 32 /* arbitrary */
	w.workers.Add(numDeleters)
	for range numDeleters {
		go w.deleterMain(deleterCtx)
	}
	return w, nil
}

func (w *ParallelWriter) initTmpFmt() {
	// Generate the format string used to name temporary objects created by
	// this ParallelWriter. Ideally we would put these somewhere near the
	// bucket's "root" for performance reasons, as advised by
	// https://cloud.google.com/storage/docs/request-rate#best-practices and as
	// defaulted to by `gcloud storage cp`
	// (https://cloud.google.com/sdk/gcloud/reference/topic/configurations#parallel_composite_upload_component_prefix);
	// however, permissions are usually based on object name prefixes (using
	// managed folders or IAM conditions), so we must prefix temporary object
	// names with that of the object being created.
	tmpFmtPrefix := fmt.Sprintf("%s_%%016x_part_", w.obj.ObjectName())
	w.tmpFmt = fmt.Sprintf("%s%%d_%%08x", tmpFmtPrefix)
	w.tmpFmtPrefixLen = len(fmt.Sprintf(tmpFmtPrefix, 0))
}

// Close implements stateio.AsyncWriter.Close.
func (w *ParallelWriter) Close() error {
	w.cancelWritesAndComposes(fmt.Errorf("context canceled by ParallelWriter.Close"))
	// Wait for composes to finish since this affects which objects exist (and
	// therefore need to be deleted).
	w.composes.Close()
	// Delete temporary objects.
	for _, level := range w.levels {
		if level.firstPart != nil {
			w.goDeleteRecursive(level.firstPart)
		}
		// If w.levels[i].parent != nil, then it must either be
		// w.levels[i+1].firstPart or in w.levels[i+1].parent.parts, so we'll
		// handle it in a later iteration of this loop.
	}
	w.deletes.Wait()
	w.cancelDeleters()
	w.workers.Wait()
	return nil
}

// MaxWriteBytes implements stateio.AsyncWriter.MaxWriteBytes.
func (w *ParallelWriter) MaxWriteBytes() uint64 {
	return w.maxWriteBytes
}

// MaxRanges implements stateio.AsyncWriter.MaxRanges.
func (w *ParallelWriter) MaxRanges() int {
	return w.maxRanges
}

// MaxParallel implements stateio.AsyncWriter.MaxParallel.
func (w *ParallelWriter) MaxParallel() int {
	return cap(w.subs)
}

// AddWrite implements stateio.AsyncWriter.AddWrite.
func (w *ParallelWriter) AddWrite(id int, _ stateio.SourceFile, _ memmap.FileRange, srcMap []byte) {
	leaf := w.makeLeaf(id, stateio.LocalClientMapping(srcMap))
	w.insertIntoWriteCompositionGraph(leaf)
	w.subs <- leaf
}

// AddWritev implements stateio.AsyncWriter.AddWritev.
func (w *ParallelWriter) AddWritev(id int, total uint64, _ stateio.SourceFile, _ []memmap.FileRange, srcMaps []unix.Iovec) {
	leaf := w.makeLeaf(id, stateio.LocalClientMappings(srcMaps))
	w.insertIntoWriteCompositionGraph(leaf)
	w.subs <- leaf
}

func (w *ParallelWriter) makeLeaf(id int, src stateio.LocalClientRanges) *composeLeaf {
	leaf := &composeLeaf{
		composeNode: composeNode{
			obj: w.bucket.Object(w.makePartName(0, w.prevLeaves)),
		},
		id:  id,
		src: src,
	}
	leaf.impl = leaf
	w.prevLeaves++
	return leaf
}

func (w *ParallelWriter) insertIntoWriteCompositionGraph(leaf *composeLeaf) {
	node := leaf.node()
	levelIndex := 0
	for {
		// Invariant: node.parent == nil; node.ready == false.
		if levelIndex < len(w.levels) {
			level := &w.levels[levelIndex]
			if nodePrev := level.firstPart; nodePrev != nil {
				// Create a new branch at the next level composing these two
				// nodes.
				parent := &composeBranch{
					composeNode: composeNode{
						obj: w.bucket.Object(w.makePartName(levelIndex+1, level.prevParents)),
					},
					partsMax: composeMax,
					partsLen: 2,
				}
				parent.impl = parent
				parent.parts[0] = nodePrev
				parent.parts[1] = node
				nodePrev.readyMu.Lock()
				nodePrev.parent = parent
				if nodePrev.ready {
					parent.partsReady.RacyStore(1)
				}
				nodePrev.readyMu.Unlock()
				node.readyMu.Lock()
				node.parent = parent
				node.readyMu.Unlock()
				level.firstPart = nil
				level.parent = parent
				// Since we added a new node, we need to recurse.
				levelIndex++
				node = parent.node()
				continue
			}
			if parent := level.parent; parent != nil {
				// Add this node to the existing branch at the next level.
				parent.parts[parent.partsLen] = node
				parent.partsLen++
				if parent.partsLen == composeMax {
					// This branch is now full.
					level.parent = nil
					level.prevParents++
				}
				node.readyMu.Lock()
				node.parent = parent
				node.readyMu.Unlock()
				break
			}
		} else {
			w.levels = append(w.levels, composeLevel{})
		}
		// Defer creating a branch at the next level until there is a
		// second node to compose into that branch.
		w.levels[levelIndex].firstPart = node
		break
	}
}

// Wait implements stateio.AsyncWriter.Wait.
func (w *ParallelWriter) Wait(cs []stateio.Completion, minCompletions int) ([]stateio.Completion, error) {
	return stateio.CompletionChanWait(w.cmps, cs, minCompletions)
}

// Reserve implements stateio.AsyncWriter.Reserve.
func (w *ParallelWriter) Reserve(n uint64) {
	// no-op
}

// Finalize implements stateio.AsyncWriter.Finalize.
func (w *ParallelWriter) Finalize() error {
	if log.IsLogging(log.Debug) {
		log.Debugf("Finalizing %s", w.obj.ObjectName())
	}

	// Collect all remaining objects to be composed in the order that they
	// should appear in the final object, regardless of their level.
	nodes := w.getEventuallyReadyNodes()

	// Discard the previous composition graph, and transfer responsibility for
	// deleting remaining temporary objects from w.Close() to us.
	levelBase := len(w.levels) - 1
	w.levels = nil

	if len(nodes) == 0 {
		// This is only possible if nothing was written, and needs to be
		// special-cased.
		sw := w.obj.NewWriter(w.writerCtx)
		sw.ChunkSize = 1
		sw.ContentType = contentType
		// Force standard storage class for consistent behavior.
		sw.StorageClass = "STANDARD"
		if err := sw.Close(); err != nil {
			if code, ok := httpCodeFromError(err); ok && isPermissionDeniedCode(code) {
				log.Infof("gcs.ParallelWriter.Finalize returning EACCES for empty write error: %v", err)
				return unix.EACCES
			}
			return fmt.Errorf("failed to write empty %s: %w", w.obj.ObjectName(), err)
		}
		if log.IsLogging(log.Debug) {
			log.Debugf("Wrote empty %s", w.obj.ObjectName())
		}
		return nil
	}

	if len(nodes) == 1 {
		// nodes[0] might be a branch; wait for it to become ready.
		w.composes.Close()
		if w.composeErr != nil {
			if code, ok := httpCodeFromError(w.composeErr); ok && isPermissionDeniedCode(code) {
				log.Infof("gcs.ParallelWriter.Finalize returning EACCES for composition error: %v", w.composeErr)
				return unix.EACCES
			}
			return fmt.Errorf("object composition failed: %w", w.composeErr)
		}
		src := nodes[0].obj
		// The documentation for storage.ObjectHandle.Move() claims that it "is
		// in preview and is not yet publicly available", but the GCS
		// documentation
		// (https://cloud.google.com/storage/docs/copying-renaming-moving-objects#atomic-rename)
		// has no such disclaimer, so try Move() before copy-and-delete.
		attrs, err := src.Move(w.writerCtx, storage.MoveObjectDestination{
			Object: w.obj.ObjectName(),
		})
		if err == nil {
			if log.IsLogging(log.Debug) {
				log.Debugf("Renamed %s (%.1f MiB) from %s", w.obj.ObjectName(), float64(attrs.Size)/float64(1<<20), src.ObjectName())
			}
			return nil
		}
		log.Infof("Renaming %s from %s failed: %v; falling back to copying", w.obj.ObjectName(), src.ObjectName(), err)
		c := w.obj.CopierFrom(src)
		// It's not clear if attributes are copied automatically, so set them
		// explicitly:
		c.ContentType = contentType
		c.StorageClass = "STANDARD"
		attrs, err = c.Run(w.writerCtx)
		w.goDelete(nodes[0])
		if err != nil {
			return fmt.Errorf("failed to copy %s from %s: %w", w.obj.ObjectName(), src.ObjectName(), err)
		}
		if log.IsLogging(log.Debug) {
			log.Debugf("Copied %s (%.1f MiB) from %s", w.obj.ObjectName(), float64(attrs.Size)/float64(1<<20), src.ObjectName())
		}
		return nil
	}

	// Build a new composition tree with remaining objects.
	root, newReadyBranches := w.buildFinalCompositionTree(nodes, levelBase)

	// Perform remaining composition.
	for _, branch := range newReadyBranches {
		if !w.composes.Enter() {
			// This shouldn't be possible since the only functions that can
			// call w.composes.Close() are w.Finalize() and w.Close(), neither
			// of which can be called concurrently with, or before,
			// w.Finalize().
			return fmt.Errorf("ParallelWriter.composes.Enter failed unexpectedly")
		}
		go w.compose(w.writerCtx, branch)
	}
	w.composes.Close()
	if w.composeErr != nil {
		// Delete temporary files.
		w.goDeleteRecursive(root.node())
		if code, ok := httpCodeFromError(w.composeErr); ok && isPermissionDeniedCode(code) {
			log.Infof("gcs.ParallelWriter.Finalize returning EACCES for composition error: %v", w.composeErr)
			return unix.EACCES
		}
		return fmt.Errorf("object composition failed: %w", w.composeErr)
	}
	return nil
}

// Preconditions: All leaves are ready; i.e. no writes are enqueued or
// inflight, and all writes have completed successfully.
func (w *ParallelWriter) getEventuallyReadyNodes() (nodes []*composeNode) {
	for levelIndex := len(w.levels) - 1; levelIndex >= 0; levelIndex-- {
		level := &w.levels[levelIndex]
		if node := level.firstPart; node != nil {
			for {
				node.readyMu.Lock()
				if node.ready {
					node.readyMu.Unlock()
					nodes = append(nodes, node)
					break
				}
				// By precondition, node must be a branch.
				branch := node.impl.(*composeBranch)
				// Note that all of branch.parts[:branch.partsLen-1] must
				// already consist of leaves or recursively-full branches
				// (because otherwise branch.parts[branch.partsLen]
				// wouldn't have been created), so they are either ready or
				// will be made ready by an existing composer.
				//
				// If branch.partsLen == composeMax, and
				// branch.parts[composeMax-1] is a leaf or recursively-full
				// branch, then an existing composer will eventually make
				// branch ready as well, so we should add branch to nodes.
				// Otherwise, add branch.parts[:branch.partsLen-1], then
				// recurse into branch.parts[branch.partsLen-1].
				if branch.isRecursivelyFull() {
					node.readyMu.Unlock()
					nodes = append(nodes, branch.node())
					break
				}
				node.readyMu.Unlock()
				nodes = append(nodes, branch.parts[:branch.partsLen-1]...)
				node = branch.parts[branch.partsLen-1].node()
			}
		}
		// If level.parent != nil, then it must either be
		// w.levels[levelIndex+1].firstPart or in
		// w.levels[levelIndex+1].parent.parts, so we've already handled it in
		// a previous iteration of this loop.
	}
	return
}

// Preconditions: b.readyMu must be locked.
func (b *composeBranch) isRecursivelyFull() bool {
	for {
		if b.partsLen != composeMax {
			return false
		}
		switch lastPart := b.parts[composeMax-1].impl.(type) {
		case *composeLeaf:
			return true
		case *composeBranch:
			b = lastPart
		default:
			panic(fmt.Sprintf("unknown composeNode.impl %T", lastPart))
		}
	}
}

// Preconditions: len(nodes) > 1.
func (w *ParallelWriter) buildFinalCompositionTree(nodes []*composeNode, levelBase int) (root *composeBranch, readyBranches []*composeBranch) {
	// In order to minimize the total number of compositions, each
	// composition will take composeMax source objects, except for at most
	// one composition (termed the "sub-maximal" composition below.)
	//
	// The time taken by a composition seems to scale with the size of the
	// resulting composite object, so critical-path composition time is
	// minimized by minimizing the size of temporary objects at lower
	// levels of the composition tree. Lower-indexed nodes tend to
	// represent larger objects than higher-indexed nodes, since
	// lower-indexed nodes were found at higher levels in the old
	// composition tree and are therefore the result of more compositions.
	// Thus:
	//
	// - Delay composing the lowest-indexed nodes until the final
	// composition of the destination object (whose size is fixed
	// regardless of composition strategy).
	//
	// - Form the sub-maximal composition out of the next lowest-indexed
	// nodes.
	//
	// - Form maximal compositions out of the highest-indexed nodes.
	//
	// To identify which nodes participate in the sub-maximal composition,
	// observe that each maximal composition reduces the number of objects
	// by composeMax-1, and the final goal is to have a single object, so
	// the sub-maximal composition must reduce the number of objects by
	// (len(nodes)-1)%(composeMax-1).
	//
	// As an example, suppose that after 5119 writes, we have gathered the
	// following 66 objects:
	//
	// - Level 0: objects 5088-5118
	//
	// - Level 1: objects 128-158
	//
	// - Level 2: objects 0-3
	//
	// The sub-maximal composition must reduce the number of objects by
	// 65%31=3, i.e. it takes 4 source objects, leaving 62 objects to
	// participate in maximal compositions. The 32 smallest objects are
	// composed into a larger temporary object; the sub-maximal composition
	// takes the next 4 smallest objects; and the final composition takes
	// the products of these compositions and the 30 largest objects. Thus,
	// the resulting composition tree is:
	//
	// - Level 3, object 0 composes the 4 objects: level 1, objects 154-157
	//
	// - Level 3, object 1 composes the 32 objects: level 1, object 158;
	// level 0, objects 5088-5118
	//
	// - The final object composes the 32 objects: level 2, objects 0-3;
	// level 1, objects 128-153; level 3, objects 0-1
	subMaxReduction := (len(nodes) - 1) % (composeMax - 1)
	subMaxParts := 0
	if subMaxReduction != 0 {
		subMaxParts = subMaxReduction + 1
	}
	levelIndex := 0
	for {
		maxParts := len(nodes) - subMaxParts
		numFullBranches := maxParts / composeMax
		numLeftoverNodes := maxParts - (numFullBranches * composeMax)
		numNextNodes := numLeftoverNodes + numFullBranches
		if subMaxParts != 0 {
			numNextNodes++
		}
		var nextNodes []*composeNode
		if numNextNodes > 1 {
			nextNodes = append(make([]*composeNode, 0, numNextNodes), nodes[:numLeftoverNodes]...)
		}
		nodes = nodes[numLeftoverNodes:]
		partIndex := uint64(0)
		for len(nodes) != 0 {
			numParts := composeMax
			if subMaxParts != 0 {
				numParts = subMaxParts
				subMaxParts = 0
			}
			var parentObj *storage.ObjectHandle
			if numNextNodes == 1 {
				parentObj = w.obj
			} else {
				parentObj = w.bucket.Object(w.makePartName(levelBase+levelIndex, partIndex))
			}
			parent := &composeBranch{
				composeNode: composeNode{
					obj: parentObj,
				},
				mixed:    true,
				partsMax: uint32(numParts),
				partsLen: uint32(numParts),
			}
			parent.impl = parent
			copy(parent.parts[:], nodes)
			parentPartsReady := uint32(0)
			for _, node := range nodes[:numParts] {
				node.readyMu.Lock()
				node.parent = parent
				if node.ready {
					parentPartsReady = parent.partsReady.Add(1)
				}
				node.readyMu.Unlock()
			}
			if parentPartsReady == parent.partsMax {
				readyBranches = append(readyBranches, parent)
			}
			if numNextNodes == 1 {
				root = parent
				return
			}
			nextNodes = append(nextNodes, parent.node())
			nodes = nodes[numParts:]
			partIndex++
		}
		// Continue to the next level.
		nodes = nextNodes
		levelIndex++
	}
}

func (w *ParallelWriter) makePartName(levelIndex int, partIndex uint64) string {
	return fmt.Sprintf(w.tmpFmt, rand.Uint64(), levelIndex, partIndex)
}

func (w *ParallelWriter) nameTempObjsForLogging(objs []*storage.ObjectHandle, mixed bool) string {
	if len(objs) == 0 {
		return "[]"
	}
	if len(objs) == 1 {
		return fmt.Sprintf("[%s]", objs[0].ObjectName()[w.tmpFmtPrefixLen:])
	}
	if !mixed {
		return fmt.Sprintf("%s through %s", objs[0].ObjectName()[w.tmpFmtPrefixLen:], objs[len(objs)-1].ObjectName()[w.tmpFmtPrefixLen:])
	}
	var b strings.Builder
	b.WriteByte('[')
	var sep string
	for _, obj := range objs {
		b.WriteString(sep)
		b.WriteString(obj.ObjectName()[w.tmpFmtPrefixLen:])
		sep = " "
	}
	b.WriteByte(']')
	return b.String()
}

func (w *ParallelWriter) writerMain(ctx context.Context) {
	defer w.workers.Done()

	// If storage.Writer.ChunkSize is non-zero, storage.Writer will allocate a
	// temporary buffer of that size. ChunkSize defaults to 16MiB, which given
	// our writer parallelism results in significant memory overhead; reducing
	// ChunkSize reduces performance by forcing each write to GCS to be
	// smaller. Setting ChunkSize to zero disables this buffering, but prevents
	// storage.Writer from automatically retrying transiently-failed writes.
	// Consequently, we need to set ChunkSize to zero in storage.Writers we
	// create, and handle retries and backoff ourselves.
	bo := backoff.ExponentialBackOff{
		// These follow the defaults of
		// https://pkg.go.dev/github.com/googleapis/gax-go/v2#Backoff, except
		// for InitialInterval and MaxElapsedTime which are taken from
		// https://github.com/googleapis/google-api-go-client/blob/main/internal/gensupport/retry.go's
		// backoff and defaultRetryDeadline respectively. However, gax-go
		// randomizes actual retry interval between 1ns and nominal retry
		// interval, while the backoff package randomizes actual retry interval
		// between nominal retry interval * 1-RandomizationFactor and nominal
		// retry interval * 1+RandomizationFactor, so the interval values here
		// are halved compared to gax-go values.
		InitialInterval:     50 * time.Millisecond,
		RandomizationFactor: 1.0,
		Multiplier:          2.0,
		MaxInterval:         15 * time.Second,
		MaxElapsedTime:      32 * time.Second,
		Clock:               backoff.SystemClock,
	}
	backoffTimer := time.NewTimer(0)
	for {
		select {
		case <-ctx.Done():
			return
		case sub := <-w.subs:
			bo.Reset()
		retry:
			sw := sub.obj.NewWriter(ctx)
			sw.ChunkSize = 0
			// Set Content-Type explicitly to avoid wasting time on
			// Content-Type autodetection.
			sw.ContentType = contentType
			// Ensure that temporary objects have standard storage class to
			// avoid early deletion fees.
			sw.StorageClass = "STANDARD"
			var done uint64
			var writeErr error
			for _, src := range sub.src.Mappings {
				n, err := sw.Write(src)
				done += uint64(n)
				if err != nil {
					writeErr = err
					break
				}
			}
			closeErr := sw.Close()
			// Only return the first error.
			doneErr := writeErr
			if doneErr == nil {
				doneErr = closeErr
			}
			if doneErr != nil {
				if shouldRetry(doneErr) {
					if nbo := bo.NextBackOff(); nbo != backoff.Stop {
						backoffTimer.Reset(nbo)
						select {
						case <-ctx.Done():
							backoffTimer.Stop()
							// don't retry
						case <-backoffTimer.C:
							if log.IsLogging(log.Debug) {
								log.Debugf("Retrying temporary object write after error: %v", doneErr)
							}
							goto retry
						}
					}
				}
				if code, ok := httpCodeFromError(doneErr); ok && isPermissionDeniedCode(code) {
					log.Infof("gcs.ParallelWriter returning EACCES for error: %v", doneErr)
					doneErr = unix.EACCES
				}
			} else {
				// Set sub.obj's generation so that it can be deleted even if
				// the bucket has object versioning enabled.
				sub.obj = sub.obj.Generation(sw.Attrs().Generation)
				// Mark this leaf as ready, and initiate any composition that
				// doing so unblocks.
				var readyParent *composeBranch
				sub.readyMu.Lock()
				sub.ready = true
				if sub.parent != nil && sub.parent.partsReady.Add(1) == sub.parent.partsMax {
					readyParent = sub.parent
				}
				sub.readyMu.Unlock()
				if readyParent != nil {
					if w.composes.Enter() {
						go w.compose(ctx, readyParent)
					}
				}
			}
			w.cmps <- stateio.Completion{
				ID:  sub.id,
				N:   done,
				Err: doneErr,
			}
		}
	}
}

func (w *ParallelWriter) compose(ctx context.Context, branch *composeBranch) {
	defer w.composes.Leave()
	srcs := make([]*storage.ObjectHandle, 0, composeMax)
	for {
		if branch.partsLen != branch.partsMax || branch.partsReady.RacyLoad() != branch.partsMax {
			panic(fmt.Sprintf("composition got %d/%d ready parts, want %d/%d", branch.partsReady.RacyLoad(), branch.partsLen, branch.partsMax, branch.partsMax))
		}
		srcs = appendNodeObjs(branch.parts[:branch.partsLen], srcs[:0])
		c := branch.obj.ComposerFrom(srcs...)
		c.ContentType = contentType
		// "The composite object that results from a composition: Has the same
		// storage class as the source objects."
		// - https://cloud.google.com/storage/docs/composite-objects.
		// So we don't need to set c.StorageClass here.
		attrs, composeErr := c.Run(ctx)
		w.goDelete(branch.parts[:branch.partsLen]...)
		if composeErr != nil {
			log.Warningf("Composition of %s from parts %s failed: %v", branch.obj.ObjectName(), w.nameTempObjsForLogging(srcs, branch.mixed), composeErr)
			w.composeErrOnce.Do(func() { w.composeErr = composeErr })
			break
		}
		if log.IsLogging(log.Debug) {
			log.Debugf("Composed %s (%.1f MiB) from parts %s", branch.obj.ObjectName(), float64(attrs.Size)/float64(1<<20), w.nameTempObjsForLogging(srcs, branch.mixed))
		}
		// Set branch.obj's generation so that it can be deleted even if the
		// bucket has object versioning enabled.
		branch.obj = branch.obj.Generation(attrs.Generation)
		var readyParent *composeBranch
		branch.readyMu.Lock()
		branch.ready = true
		if branch.parent != nil && branch.parent.partsReady.Add(1) == branch.parent.partsMax {
			readyParent = branch.parent
		}
		// Forget parts so that they can be garbage-collected.
		clear(branch.parts[:branch.partsLen])
		branch.readyMu.Unlock()
		if readyParent == nil {
			break
		}
		// Recurse into the parent:
		branch = readyParent
	}
}

func (w *ParallelWriter) deleterMain(ctx context.Context) {
	defer w.workers.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case obj := <-w.delete:
			// Use context.Background() here since we don't want ParallelWriter
			// cancelation or closure to cancel deletions.
			if err := obj.Delete(context.Background()); err != nil {
				log.Warningf("Deletion of %s failed: %v", obj.ObjectName(), err)
			}
			w.deletes.Done()
		}
	}
}

func (w *ParallelWriter) goDelete(nodes ...*composeNode) {
	for _, node := range nodes {
		node.readyMu.Lock()
		if !node.ready {
			node.readyMu.Unlock()
			continue
		}
		node.ready = false
		node.readyMu.Unlock()
		w.deletes.Add(1)
		w.delete <- node.obj
	}
}

func (w *ParallelWriter) goDeleteRecursive(nodes ...*composeNode) {
	for _, node := range nodes {
		w.goDelete(node)
		if branch, ok := node.impl.(*composeBranch); ok {
			w.goDeleteRecursive(branch.parts[:branch.partsLen]...)
		}
	}
}
