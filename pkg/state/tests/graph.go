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

package tests

import (
	"context"
	"fmt"
	"math/rand"
	"sync/atomic"
)

// +stateify savable
type gRoot struct {
	first   *gNode
	entries []*gNode
	any     any
	all     []*gNode
}

// +stateify savable
type gInner struct {
	x int64
	p *gNode
	s string
}

// +stateify savable
type gKey struct {
	a int32
	b string
}

// +stateify savable
type gPlain struct {
	a      int32
	b      uint8
	c      [3]uint16
	f      float64
	flag   bool
	nested gPlainInner
}

// +stateify savable
type gPlainInner struct {
	x uint64
}

// +stateify savable
type gSaved struct {
	v int64
	n *gNode
}

type gID int64

type gIface interface {
	gID() gID
}

func (n *gNode) gID() gID { return gID(n.id) }

// +stateify savable
type gNode struct {
	id    int64
	name  string
	flag  bool
	small uint8
	i16   int16
	f32   float32
	f64   float64
	c128  complex128
	raw   [7]byte
	nums  [3]uint16

	next  *gNode
	other *gNode

	inner gInner
	arr   [2]gInner

	innerPtr *gInner
	intPtr   *int64
	bytePtr  *byte

	nodes  []*gNode
	vals   []gInner
	window []gInner
	blob   []byte
	strs   []string

	byID      map[int64]*gNode
	keyed     map[gKey]*gNode
	byNode    map[*gNode]int
	inners    map[int32]gInner
	shared    map[string]int64
	sharedPtr *map[string]int64

	iface  any
	ifaces []any

	plain    gPlain
	plains   []gPlain
	plainPtr *int32

	impls    []gIface
	implsArr *[2]gIface
	byGID    map[gID]*gNode
	gidPtr   *gID
	gid      gID

	waitFor *gNode `state:"wait"`

	later [2]*gNode

	saved     int64 `state:".(gSaved)"`
	savedNode *gNode

	alias atomic.Pointer[gNode] `state:".(*gNode)"`

	saveCalls int  `state:"nosave"`
	loaded    bool `state:"nosave"`
	skipped   int  `state:"nosave"`
}

func (n *gNode) beforeSave() {
	n.saveCalls++
}

func (n *gNode) afterLoad(context.Context) {
	if n.waitFor != nil && !n.waitFor.loaded {
		panic(fmt.Sprintf("node %d loaded before node %d that it waits for", n.id, n.waitFor.id))
	}
	if a := n.alias.Load(); a != nil && !a.loaded {
		panic(fmt.Sprintf("node %d loaded before node %d in its alias", n.id, a.id))
	}
	for _, l := range n.later {
		if l != nil && !l.loaded {
			panic(fmt.Sprintf("node %d loaded before node %d in its array", n.id, l.id))
		}
	}
	n.loaded = true
}

func (n *gNode) saveSaved() gSaved {
	return gSaved{v: n.saved, n: n.savedNode}
}

func (n *gNode) loadSaved(_ context.Context, s gSaved) {
	n.saved = s.v
	if s.n != n.savedNode {
		panic(fmt.Sprintf("node %d: saved pointer %p differs from savedNode %p", n.id, s.n, n.savedNode))
	}
}

func (n *gNode) saveAlias() *gNode {
	return n.alias.Load()
}

func (n *gNode) loadAlias(_ context.Context, p *gNode) {
	n.alias.Store(p)
}

type graphOptions struct {
	nodes   int
	all     bool
	windows bool
}

// randomGraph builds a random object graph. It is deterministic for a given
// seed and options.
func randomGraph(seed int64, opts graphOptions) *gRoot {
	if opts.nodes <= 0 {
		panic("opts.nodes must be positive")
	}
	r := rand.New(rand.NewSource(seed))
	nodes := make([]*gNode, opts.nodes)
	for i := range nodes {
		nodes[i] = randomNode(r, i)
	}
	pick := func() *gNode {
		if r.Intn(4) == 0 {
			return nil
		}
		return nodes[r.Intn(len(nodes))]
	}
	pickNonNil := func() *gNode {
		return nodes[r.Intn(len(nodes))]
	}
	for i, n := range nodes {
		n.next = pick()
		n.other = pick()
		n.inner.p = pick()
		n.arr[0].p = pick()
		n.arr[1].p = pick()
		for j := range n.vals {
			n.vals[j].p = pick()
		}
		n.savedNode = pick()

		// Interior pointers.
		switch t := pickNonNil(); r.Intn(5) {
		case 0:
			n.innerPtr = &t.inner
		case 1:
			n.innerPtr = &t.arr[r.Intn(2)]
		case 2:
			if len(t.vals) > 0 {
				n.innerPtr = &t.vals[r.Intn(len(t.vals))]
			}
		case 3:
			n.innerPtr = &gInner{x: r.Int63(), p: pick()}
		}
		switch t := pickNonNil(); r.Intn(6) {
		case 0:
			n.intPtr = &t.id
		case 1:
			n.intPtr = &t.inner.x
		case 2:
			n.intPtr = &t.arr[r.Intn(2)].x
		case 3:
			if len(t.vals) > 0 {
				n.intPtr = &t.vals[r.Intn(len(t.vals))].x
			}
		case 4:
			v := r.Int63()
			n.intPtr = &v
		}
		switch t := pickNonNil(); r.Intn(3) {
		case 0:
			n.bytePtr = &t.raw[r.Intn(len(t.raw))]
		case 1:
			if len(t.blob) > 0 {
				n.bytePtr = &t.blob[r.Intn(len(t.blob))]
			}
		}

		// Slices.
		switch r.Intn(4) {
		case 0:
			// Leave nil.
		case 1:
			n.nodes = []*gNode{}
		default:
			l := r.Intn(5)
			n.nodes = make([]*gNode, l, l+r.Intn(3))
			for j := range n.nodes {
				n.nodes[j] = pick()
			}
		}
		if t := pickNonNil(); opts.windows && len(t.vals) > 0 && r.Intn(3) == 0 {
			lo := r.Intn(len(t.vals))
			hi := lo + r.Intn(len(t.vals)-lo+1)
			n.window = t.vals[lo:hi]
		}

		// Maps.
		if r.Intn(3) != 0 {
			n.byID = make(map[int64]*gNode)
			for j := r.Intn(4); j > 0; j-- {
				t := pickNonNil()
				n.byID[t.id] = t
			}
		}
		if r.Intn(2) == 0 {
			n.keyed = make(map[gKey]*gNode)
			for j := r.Intn(4); j > 0; j-- {
				n.keyed[gKey{a: r.Int31(), b: fmt.Sprintf("k%d", r.Intn(10))}] = pick()
			}
		}
		if r.Intn(2) == 0 {
			n.inners = make(map[int32]gInner)
			for j := r.Intn(6); j > 0; j-- {
				var v gInner
				if r.Intn(2) == 0 {
					v.x = r.Int63()
				}
				if r.Intn(2) == 0 {
					v.p = pick()
				}
				if r.Intn(2) == 0 {
					v.s = fmt.Sprintf("v%d", r.Intn(10))
				}
				n.inners[r.Int31()] = v
			}
		}
		if opts.all && r.Intn(2) == 0 {
			n.byNode = make(map[*gNode]int)
			for j := r.Intn(4); j > 0; j-- {
				n.byNode[pickNonNil()] = r.Int()
			}
		}
		if i > 0 && r.Intn(3) == 0 {
			n.shared = nodes[r.Intn(i)].shared
		} else if r.Intn(4) != 0 {
			n.shared = map[string]int64{fmt.Sprintf("s%d", i): int64(i)}
		}
		if r.Intn(3) == 0 {
			n.sharedPtr = &pickNonNil().shared
		}

		// Plain data.
		n.plain = randomPlain(r)
		if r.Intn(2) == 0 {
			n.plains = make([]gPlain, r.Intn(4))
			for j := range n.plains {
				n.plains[j] = randomPlain(r)
			}
		}
		switch t := pickNonNil(); r.Intn(3) {
		case 0:
			n.plainPtr = &t.plain.a
		case 1:
			if len(t.plains) > 0 {
				n.plainPtr = &t.plains[r.Intn(len(t.plains))].a
			}
		}

		// Unregistered named types.
		if r.Intn(2) == 0 {
			n.impls = make([]gIface, r.Intn(4))
			for j := range n.impls {
				if p := pick(); p != nil {
					n.impls[j] = p
				}
			}
		}
		if r.Intn(3) == 0 {
			n.implsArr = &[2]gIface{pickNonNil(), nil}
		}
		if r.Intn(2) == 0 {
			n.byGID = make(map[gID]*gNode)
			for j := r.Intn(3); j > 0; j-- {
				t := pickNonNil()
				n.byGID[t.gID()] = t
			}
		}
		if r.Intn(3) == 0 {
			v := gID(r.Int63())
			n.gidPtr = &v
		}
		n.gid = gID(r.Int63())

		// Interfaces.
		n.iface = randomAny(r, nodes, pick)
		if r.Intn(2) == 0 {
			n.ifaces = make([]any, r.Intn(5))
			for j := range n.ifaces {
				n.ifaces[j] = randomAny(r, nodes, pick)
			}
		}

		// Wait dependencies only go to later nodes.
		if i+1 < len(nodes) && r.Intn(3) == 0 {
			n.waitFor = nodes[i+1+r.Intn(len(nodes)-i-1)]
		}
		if i+1 < len(nodes) && r.Intn(3) == 0 {
			n.alias.Store(nodes[i+1+r.Intn(len(nodes)-i-1)])
		}
		for j := range n.later {
			if i+1 < len(nodes) && r.Intn(3) == 0 {
				n.later[j] = nodes[i+1+r.Intn(len(nodes)-i-1)]
			}
		}
	}

	root := &gRoot{first: nodes[0]}
	for j := r.Intn(4); j > 0; j-- {
		root.entries = append(root.entries, pickNonNil())
	}
	root.any = randomAny(r, nodes, pick)
	if opts.all {
		root.all = nodes
	}
	return root
}

func randomNode(r *rand.Rand, i int) *gNode {
	n := &gNode{
		id:      int64(i)<<20 | r.Int63n(1<<20),
		name:    fmt.Sprintf("node-%d", i),
		flag:    r.Intn(2) == 0,
		small:   uint8(r.Intn(256)),
		i16:     int16(r.Intn(1<<16) - 1<<15),
		f32:     r.Float32(),
		f64:     r.NormFloat64(),
		c128:    complex(r.Float64(), -r.Float64()),
		inner:   gInner{x: r.Int63(), s: fmt.Sprintf("inner-%d", i)},
		saved:   r.Int63(),
		skipped: i + 1,
	}
	r.Read(n.raw[:])
	for j := range n.nums {
		n.nums[j] = uint16(r.Intn(1 << 16))
	}
	for j := range n.arr {
		n.arr[j].x = r.Int63()
	}
	if l := r.Intn(5); l > 0 || r.Intn(2) == 0 {
		n.vals = make([]gInner, l, l+r.Intn(3))
		for j := range n.vals {
			n.vals[j] = gInner{x: r.Int63(), s: fmt.Sprintf("val-%d-%d", i, j)}
		}
	}
	switch r.Intn(3) {
	case 0:
		n.blob = make([]byte, r.Intn(40))
		r.Read(n.blob)
	case 1:
		n.blob = []byte{}
	}
	for j := r.Intn(3); j > 0; j-- {
		n.strs = append(n.strs, fmt.Sprintf("str-%d", r.Int()))
	}
	return n
}

func randomPlain(r *rand.Rand) gPlain {
	p := gPlain{a: r.Int31(), b: uint8(r.Intn(256)), f: r.NormFloat64(), flag: r.Intn(2) == 0}
	for i := range p.c {
		p.c[i] = uint16(r.Intn(1 << 16))
	}
	p.nested.x = r.Uint64()
	return p
}

func randomAny(r *rand.Rand, nodes []*gNode, pick func() *gNode) any {
	t := nodes[r.Intn(len(nodes))]
	switch r.Intn(12) {
	case 0:
		return nil
	case 1:
		return pick()
	case 2:
		return gInner{x: r.Int63(), p: pick(), s: "boxed"}
	case 3:
		return &t.inner
	case 4:
		return r.Int63()
	case 5:
		return fmt.Sprintf("any-%d", r.Int())
	case 6:
		return []int64{r.Int63(), r.Int63()}
	case 7:
		return t.shared
	case 8:
		return &t.id
	case 9:
		return [2]int32{r.Int31(), r.Int31()}
	case 10:
		if r.Intn(2) == 0 {
			return randomPlain(r)
		}
		return gKey{a: r.Int31(), b: "iface"}
	default:
		return uint8(r.Intn(256))
	}
}

// +stateify savable
type gBytesRoot struct {
	b   [1]byte
	arr [3]byte
	n   int64
	s   string
}
