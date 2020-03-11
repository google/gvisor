// Copyright 2020 The gVisor Authors.
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

// Package ctrie provides a thread-safe, lock-free implementation of a
// hash-based trie. This structure is suitable to storing unordered data, and
// will scale well given concurrent modification.
//
// The implementation is derived directly from the paper:
// http://aleksandar-prokopec.com/resources/docs/ctries-snapshot.pdf
//
// Clients using this package must use the go_template_instance rule in
// tools/go_generics/defs.bzl to create an instantiation of this template
// package, providing types to use in place of Key and Value interfaces.
package ctrie

import (
	"math/bits"
)

// Key is a type parameter that must be hashable.
type Key interface {
	Hash() uint32
	Equal(Key) bool
}

// Value is a required type parameter.
type Value interface{}

const (
	// bitsPerLevel is the number of bits encoded in each level of the tree.
	//
	// This will result in (1 << bitsPerLevel) pointers. More space may be
	// wasted per level at the expense of extra traversals. The default here
	// is probably the right answer for most cases.
	bitsPerLevel = 5
)

const (
	typeSNode uint32 = iota
	typeINode
	typeCNode
	typeTNode
	typeLNode
)

// pair is a (Key, Value) pair.
//
// +stateify
type pair struct {
	key   Key
	value Value
}

// sNode is a value node in the tree.
//
// This is immutable.
type sNode struct {
	typeDWord uint32
	hash      uint32
	pair      pair
}

// newSNode constructs a sNode.
func newSNode(k Key, v Value, hash uint32) *sNode {
	return &sNode{
		typeDWord: typeSNode,
		hash:      hash,
		pair: pair{
			key:   k,
			value: v,
		},
	}
}

// iNode is an intermediate node in the tree.
//
// This is mutable; main may be updated.
type iNode struct {
	typeDWord uint32
	main      mainNode
}

// newINode constructs a new iNode.
func newINode(mn mainNode) *iNode {
	return &iNode{
		typeDWord: typeINode,
		main:      mn,
	}
}

// tNode is a tombstone node.
type tNode struct {
	typeDWord uint32
	sNode     *sNode
}

// newTNode constructs a new tNode.
func newTNode(s *sNode) *tNode {
	return &tNode{
		typeDWord: typeTNode,
		sNode:     s,
	}
}

// lNode is a list node (for hash collisions).
//
// This is immutable.
type lNode struct {
	typeDWord uint32
	sNodes    []*sNode
}

// newLNode returns a new LNode given (Key, Value) pairs.
func newLNode(s ...*sNode) *lNode {
	return &lNode{
		typeDWord: typeLNode,
		sNodes:    s,
	}
}

// Insert returns a new *lNode containing the given pair.
func (l *lNode) Insert(s *sNode) *lNode {
	// Scan for an existing match.
	for index, os := range l.sNodes {
		if os.pair.key.Equal(s.pair.key) {
			sNodes := make([]*sNode, len(l.sNodes))
			copy(sNodes, l.sNodes)
			sNodes[index] = s // Replace.
			return &lNode{
				typeDWord: typeLNode,
				sNodes:    sNodes,
			}
		}
	}
	// Return an appended version.
	return &lNode{
		typeDWord: typeLNode,
		// N.B. We construct a new slice here because the other slice
		// may be modified concurrently by another writer.
		sNodes: append([]*sNode{s}, l.sNodes...),
	}
}

// Remove returns a new node with the given key removed.
func (l *lNode) Removed(k Key, v *Value) (mainNode, bool) {
	sNodes := make([]*sNode, 0, len(l.sNodes))
	found := false
	for _, s := range l.sNodes {
		if s.pair.key.Equal(k) {
			*v = s.pair.value
			found = true
			continue
		}
		sNodes = append(sNodes, s)
	}
	if !found {
		return mainNode(l), false
	}
	if len(sNodes) == 1 {
		// Entomb if there is only one item.
		return mainNode(newTNode(sNodes[0])), true
	}
	return mainNode(&lNode{
		typeDWord: typeLNode,
		sNodes:    sNodes,
	}), true
}

// Lookup looks up a given key.
func (l *lNode) Lookup(k Key, hash uint32, v *Value) bool {
	for _, s := range l.sNodes {
		if s.hash == hash && s.pair.key.Equal(k) {
			*v = s.pair.value // Found.
			return true
		}
	}
	return false
}

// cNode is a node containing an array of other nodes.
//
// This is immutable.
type cNode struct {
	typeDWord uint32

	// bmp is a bit mask of valid entries in the array below.  See the
	// flagPos function for information about how this is used to make
	// entries into the array.
	//
	// Note that the width of the this type determines limits on the value
	// of bitsPerLevel; this is checked in init() below.
	bmp uint32

	// Array is the set of pointers for this level. Note that this is an
	// actual array type, not a slice. While a slice may be more space
	// efficient, it requires an extra level of indirection. We still use
	// the bmp trick to pack entries and improve locality, but we still
	// have a complete array of entries here.
	array [1 << bitsPerLevel]mainNode // One of iNode, sNode.
}

const mask = (1 << bitsPerLevel) - 1

// flagPos returns the flag and position in the array.
func flagPos(hash uint32, level uint, bmp uint32) (uint32, uint32) {
	index := uint32((hash >> level) & mask)           // Index in full space.
	flag := uint32(1) << index                        // Flag in full space.
	pos := uint32(bits.OnesCount32((flag - 1) & bmp)) // Compressed position.
	return flag, pos
}

// newCNodeOrLNode constructs a new cNode recursively.
//
// This must return a cNode or an lNode.
func newCNodeOrLNode(level uint, s ...*sNode) mainNode {
	if level >= 32 {
		// We need to create a chained entry.
		return mainNode(newLNode(s...))
	}
	c := &cNode{
		typeDWord: typeCNode,
	}

	// nodes are the nodes for the array, not including iNodes.
	var nodes [1 << bitsPerLevel][]*sNode

	// Push into the array appropriately.
	for i := 0; i < len(s); i++ {
		index := (s[i].hash >> level) & mask
		c.bmp |= (1 << index)
		nodes[index] = append(nodes[index], s[i])
	}

	// Construct all entries.
	for index := 0; index < len(nodes); index++ {
		flag := uint32(1 << index)
		if c.bmp&flag == 0 {
			continue
		}
		pos := bits.OnesCount32((flag - 1) & c.bmp)
		if len(nodes[index]) > 1 {
			// Additional level of indirection (or lNode) required.
			c.array[pos] = mainNode(newINode(newCNodeOrLNode(level+bitsPerLevel, nodes[index]...)))
		} else {
			// Direct reference.
			c.array[pos] = mainNode(nodes[index][0])
		}
	}

	return mainNode(c)
}

// Updated updates the given slot.
func (c *cNode) Updated(pos uint32, mn mainNode) *cNode {
	nc := &cNode{
		typeDWord: typeCNode,
		bmp:       c.bmp,
		array:     c.array,
	}
	nc.array[pos] = mn // Updated.
	return nc
}

// Removed removes the given slot.
func (c *cNode) Removed(flag, pos uint32) *cNode {
	nc := &cNode{
		typeDWord: typeCNode,
		bmp:       c.bmp,
		array:     c.array,
	}
	nc.bmp &= ^flag
	// The removal of this position from the bmp set means that the
	// position of all other entries has now been shifted down.
	copy(nc.array[pos:], nc.array[pos+1:])
	// Zap the previous last entry, as it has now been shifted.
	nc.array[bits.OnesCount32(nc.bmp)] = nil
	return nc
}

// Insert inserts into a zero entry.
//
// Precondition: c.bmp&flag == 0.
func (c *cNode) Insert(flag uint32, s *sNode) *cNode {
	nc := &cNode{
		typeDWord: typeCNode,
		bmp:       c.bmp,
		array:     c.array,
	}
	nc.bmp |= flag
	// The removal of this position from the bmp set means that we need to
	// shift everything up one to make room. The variable 'count' is the
	// count of set flags after insertion, and 'pos' is the position after
	// insertion. However, this position is guaranteed to be occupied.
	// Therefore, we need to shift everything there upwards before
	// insertion. This needs to be done backwards.
	count := bits.OnesCount32(nc.bmp)
	pos := bits.OnesCount32((flag - 1) & nc.bmp)
	for i := count - 1; i >= pos+1; i-- {
		nc.array[i] = nc.array[i-1]
	}
	nc.array[pos] = mainNode(s)
	return nc
}

// Map is the core data structure.
//
// +stateify
type Map struct {
	root iNode `state:".([]pair)"`
}

// saveRoot saves all entries.
func (m *Map) saveRoot() (ps []pair) {
	m.Range(func(k Key, v Value) {
		ps = append(ps, pair{
			key:   k,
			value: v,
		})
	})
	return
}

// loadRoot loads all entries.
func (m *Map) loadRoot(ps []pair) {
	for _, p := range ps {
		m.Insert(p.key, p.value)
	}
}

// init initializes the Map.
func (m *Map) init() {
	CAS(&m.root.main, nil, newCNodeOrLNode(0))
}

// Insert inserts the given key and value.
func (m *Map) Insert(k Key, v Value) {
	if m.root.main == nil {
		m.init()
	}
	hash := k.Hash()
	for {
		if !m.root.insert(k, v, hash, 0, nil) {
			continue
		}
		break
	}
}

// Remove removes the given key.
func (m *Map) Remove(k Key) (v Value, ok bool) {
	if m.root.main == nil {
		ok = false
		return
	}
	hash := k.Hash()
	for {
		if !m.root.remove(k, &v, &ok, hash, 0, nil) {
			continue
		}
		break
	}
	return
}

// Lookup looks up the given key.
func (m *Map) Lookup(k Key) (v Value, ok bool) {
	if m.root.main == nil {
		ok = false
		return
	}
	hash := k.Hash()
	for {
		if !m.root.lookup(k, &v, &ok, hash, 0, nil) {
			continue
		}
		break
	}
	return
}

// Range iterates over all keys and values.
func (m *Map) Range(fn func(k Key, v Value)) {
	m.root.walk(fn)
}

// iinsert is a low-level insert operation. It may fail.
//
// Original pseudo-code implementation:
//
// READ(i.main) match {
// case cn: CNode =>
//	flag, pos = flagpos(k.hash, lev, cn.bmp)
//	if cn.bmp & flag = 0 {
//		ncn = cn.inserted(pos, flag, SNode(k, v))
//		if CAS(i.main, cn, ncn) return OK
//		else return RESTART
//	}
//	cn.array(pos) match {
//	case sin: INode =>
//		return iinsert(sin, k, v, lev + W, i)
//	case sn: SNode =>
//		if sn.k != k {
//			nsn = SNode(k, v)
//			nin = INode(CNode(sn, nsn, lev + W))
//			ncn = cn.updated(pos, nin)
//			if CAS(i.main, cn, ncn) return OK
//			else return RESTART
//		} else {
//			ncn = cn.updated(pos, SNode(k, v))
//			if CAS(i.main, cn, ncn) return OK
//			else return RESTART
//		}
//	}
// case tn: TNode =>
//	clean(parent, lev - W)
//	return RESTART
// case ln: LNode =>
//	if CAS(i.main, ln, ln.inserted(k, v)) return OK
//	else return RESTART
// }
func (i *iNode) insert(k Key, v Value, hash uint32, level uint, parent *iNode) bool {
	c, t, l, val := CTL(&i.main)
	switch {
	case c != nil:
		flag, pos := flagPos(hash, level, c.bmp)
		if c.bmp&flag == 0 {
			ns := newSNode(k, v, hash)
			nc := c.Insert(flag, ns)
			return CAS(&i.main, val, mainNode(nc))
		}
		ni, s := IS(&c.array[pos])
		switch {
		case ni != nil:
			return ni.insert(k, v, hash, level+bitsPerLevel, i)
		case s != nil:
			ns := newSNode(k, v, hash)
			if s.pair.key.Equal(k) {
				// Update the existing entry.
				nc := c.Updated(pos, mainNode(ns))
				return CAS(&i.main, val, mainNode(nc))
			}
			ni := newINode(newCNodeOrLNode(level+bitsPerLevel, s, ns))
			nc := c.Updated(pos, mainNode(ni))
			return CAS(&i.main, val, mainNode(nc))
		default:
			// Should not happen.
			panic("flag set, but no node found")
		}
	case t != nil:
		parent.clean(level - bitsPerLevel)
		return false // Restart.
	case l != nil:
		return CAS(&i.main, val, mainNode(l.Insert(newSNode(k, v, hash))))
	default:
		// Should not happen.
		panic("unexpected node")
	}
}

// remove is a low-level remove operation. It may fail.
//
// Original pseudo-code implementation:
//
// READ(i.main) match {
// case cn: CNode =>
//	flag, pos = flagpos(k.hash, lev, cn.bmp)
//	if cn.bmp & flag = 0 return NOTFOUND
//	res = cn.array(pos) match {
//	case sin: INode =>
//		iremove(sin, k, lev + W, i)
//	case sn: SNode =>
//		if sn.k != k
//			NOTFOUND
//		else {
//			ncn = cn.removed(pos, flag)
//			cntr = toContracted(ncn, lev)
//			if CAS(i.main, cn, cntr) sn.v else RESTART
//		}
//	}
//	if res = NOTFOUND ∨ res = RESTART return res
//	if READ(i.main): TNode
//		in.cleanParent(parent, k.hash, lev - W)
//	return res
// case tn: TNode =>
//	clean(parent, lev - W)
//	return RESTART
// case ln: LNode =>
//	nln = ln.removed(k)
//	if length(nln) = 1 nln = entomb(nln.sn)
//	if CAS(i.main, ln, nln) return ln.lookup(k)
//	else return RESTART
// }
func (i *iNode) remove(k Key, v *Value, ok *bool, hash uint32, level uint, parent *iNode) bool {
	c, t, l, val := CTL(&i.main)
	switch {
	case c != nil:
		flag, pos := flagPos(hash, level, c.bmp)
		if c.bmp&flag == 0 {
			*ok = false // Not found.
			return true // No restart.
		}
		ni, s := IS(&c.array[pos])
		done := false // Return value.
		switch {
		case ni != nil:
			done = ni.remove(k, v, ok, hash, level+bitsPerLevel, i)
		case s != nil:
			if !s.pair.key.Equal(k) {
				*ok = false // Not found.
				done = true // No restart.
			} else {
				nc, _ := c.Removed(flag, pos).toContracted(level)
				if CAS(&i.main, val, mainNode(nc)) {
					*v = s.pair.value
					*ok = true  // Removed.
					done = true // No restart.
				} else {
					done = false // Restart.
				}
			}
		default:
			// Should not happen.
			panic("flag set, but no node found")
		}
		if !done || !*ok {
			return done // Restart or not found.
		}
		if _, _, t, _ := CTL(&i.main); t != nil {
			i.cleanParent(parent, hash, level-bitsPerLevel)
		}
		return true // Completed.
	case t != nil:
		parent.clean(level - bitsPerLevel)
		return false // Restart.
	case l != nil:
		mn, rOk := l.Removed(k, v)
		if !rOk {
			*ok = false // Not found.
			return true // No restart.
		}
		if CAS(&i.main, val, mainNode(mn)) {
			*ok = true  // Removed.
			return true // No restart.
		}
		return false // Restart.
	default:
		// Should not happen.
		panic("unexpected node")
	}
}

// lookup is a low-level lookup operation. It may fail.
//
// Original pseudo-code implementation:
//
// READ(i.main) match {
// case cn: CNode =>
//	flag, pos = flagpos(k.hash, lev, cn.bmp)
//	if cn.bmp & flag = 0 return NOTFOUND
//	cn.array(pos) match {
//	case sin: INode =>
//		return ilookup(sin, k, lev + W, i)
//	case sn: SNode =>
//		if sn.k = k return sn.v else return NOTFOUND
//	}
// case tn: TNode =>
//	clean(parent, lev - W)
//	return RESTART
// case ln: LNode =>
//	return ln.lookup(k)
// }
func (i *iNode) lookup(k Key, v *Value, ok *bool, hash uint32, level uint, parent *iNode) bool {
	c, t, l, _ := CTL(&i.main)
	switch {
	case c != nil:
		flag, pos := flagPos(hash, level, c.bmp)
		if c.bmp&flag == 0 {
			*ok = false // Not found.
			return true // No restart.
		}
		ni, s := IS(&c.array[pos])
		switch {
		case ni != nil:
			return ni.lookup(k, v, ok, hash, level+bitsPerLevel, i)
		case s != nil:
			if s.pair.key.Equal(k) {
				*v = s.pair.value // Value in entry.
				*ok = true        // No restart.
				return true
			}
			*ok = false // Not found.
			return true // No restart.
		default:
			panic("unexpected node")
		}
	case t != nil:
		parent.clean(level - bitsPerLevel)
		return false // Restart.
	case l != nil:
		*ok = l.Lookup(k, hash, v)
		return true // No restart.
	default:
		// Should not happen.
		panic("unexpected node")
	}
}

// walk traverses the whole tree.
func (i *iNode) walk(fn func(k Key, v Value)) {
	c, t, l, _ := CTL(&i.main)
	switch {
	case c != nil:
		// Iterate over all entries.
		for i := uint32(0); i < 32; i++ {
			if c.bmp&(1<<i) != 0 {
				ni, s := IS(&c.array[i])
				switch {
				case ni != nil:
					ni.walk(fn)
				case s != nil:
					fn(s.pair.key, s.pair.value)
				}
			}
		}
	case t != nil:
		// Traverse the tombstone.
		fn(t.sNode.pair.key, t.sNode.pair.value)
	case l != nil:
		// Traverse the list.
		for _, s := range l.sNodes {
			fn(s.pair.key, s.pair.value)
		}
	}
}

// toContracted returns a pointer to either a tNode or a cNode.
//
// This returns true iff contraction happened.
//
// Original pseudo-code implementation:
//
// if lev > 0 ∧ cn.array.length = 1 {
//	cn.array(0) match {
//	case sn: SNode => return entomb(sn)
//	case _ => return cn
//	}
// } else return cn
func (c *cNode) toContracted(level uint) (mainNode, bool) {
	if level > 0 && bits.OnesCount32(c.bmp) == 1 {
		if _, s := IS(&c.array[0]); s != nil {
			return mainNode(newTNode(s)), true
		}
	}
	return mainNode(c), false
}

// toCompressed compresses the given cNode. This replaces all references in the
// cNode to tNode with the appropriate sNodes directly.
//
// This returns true iff compression happened.
//
// Original pseudo-code implementation:
//
// num = bit#(cn.bmp)
// ncn = cn.mapped(resurrect(_))
// return toContracted(ncn, lev)
func (c *cNode) toCompressed(level uint) (mainNode, bool) {
	nc := cNode{
		typeDWord: typeCNode,
		bmp:       c.bmp,
		array:     c.array,
	}
	changed := 0 // To avoid extra CAS in return.
	count := bits.OnesCount32(nc.bmp)
	for slot := 0; slot < count; slot++ {
		if i, _ := IS(&nc.array[slot]); i != nil {
			_, t, _, _ := CTL(&i.main)
			if t != nil {
				// Refer directly to the sNode.
				nc.array[slot] = mainNode(t.sNode)
				changed++
			}
		}
	}
	final, contracted := nc.toContracted(level)
	if changed > 0 || contracted {
		return final, true
	}
	return mainNode(c), false // Not changed.
}

// clean cleans the given node.
//
// Original pseudo-code implementation:
//
// m = READ(i.main)
// if m: CNode CAS(i.main, m, toCompressed(m, lev))
func (i *iNode) clean(level uint) {
	c, _, _, val := CTL(&i.main)
	if c != nil {
		nc, compressed := c.toCompressed(level)
		if compressed {
			CAS(&i.main, val, nc)
		}
	}
}

// cleanParent cleans the parent node.
//
// Original pseudo-code implementation:
//
// m, pm = READ(i.main), READ(p.main)
// pm match {
// case cn: CNode =>
//	flag, pos = flagpos(k.hash, lev, cn.bmp)
//	if bmp & flag = 0 return
//	sub = cn.array(pos)
//	if sub != i return
//	if m: TNode {
//	ncn = cn.updated(pos, resurrect(m))
//	if ¬CAS(p.main, cn, toContracted(ncn, lev))
//	cleanParent(p, i, hc, lev)
//	}
// case _ => return
// }
func (i *iNode) cleanParent(parent *iNode, hash uint32, level uint) {
	for {
		c, _, _, parentVal := CTL(&parent.main)
		if c != nil {
			flag, pos := flagPos(hash, level, c.bmp)
			if c.bmp&flag == 0 {
				return // Changed.
			}
			ni, _ := IS(&c.array[pos])
			if ni != i {
				return // Changed.
			}
			if _, t, _, _ := CTL(&i.main); t != nil {
				// Construct a new CNode that is contracted.
				nc, _ := c.Updated(pos, mainNode(t.sNode)).toContracted(level)
				if !CAS(&parent.main, parentVal, nc) {
					continue // Repeat.
				}
			}
			break // Done.
		}
	}
}

func init() {
	// Since bmp in the cNode is a 32-bit level, we can't allow
	// bitsPerLevel to exceed 5, which will index that array.
	if (1 << bitsPerLevel) > 32 {
		panic("bitsPerLevel is too high")
	}
}
