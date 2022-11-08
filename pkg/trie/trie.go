// Copyright 2022 The gVisor Authors.
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

// Package trie provides a character-based prefix trie data structure for storing arbitrary payloads
// in an efficiently retrievable manner.
package trie

// Visitor accepts a prefix string and an associated value, and returns true iff searching should
// continue deeper into the Trie. It is used by FindMatching().
type Visitor func(prefix string, value any) bool

// Trie stores data at given strings in tree structure, for linear-time retrieval.
// Call New() to obtain a valid Trie.
type Trie struct {
	root *node
	size int
}

// New creates a new instance of the Trie interface.
func New() *Trie {
	return &Trie{root: &node{children: make(map[rune]*node)}, size: 0}
}

type node struct {
	value    any
	children map[rune]*node
}

// FindPrefixes invokes the Visitor with all key-value pairs where the key is a prefix of `key`,
// including exact matches. It does this in increasing order of key length, and terminates early if
// Visitor returns false.
func (t *Trie) FindPrefixes(key string, f Visitor) {
	cur := t.root
	if cur.value != nil && !f("", cur.value) {
		return
	}

	for i, r := range key {
		next, ok := cur.children[r]
		if !ok {
			return
		}

		if next.value != nil && !f(key[:(i+1)], next.value) {
			return
		}
		cur = next
	}
}

func (t *Trie) updateNode(n *node, newValue any) {
	if n.value != nil {
		t.size--
	}
	if newValue != nil {
		t.size++
	}
	n.value = newValue
}

// SetValue associates the specified key with the given value, replacing any existing value.
func (t *Trie) SetValue(key string, value any) {
	cur := t.root
	for _, r := range key {
		next, ok := cur.children[r]
		if !ok {
			next = &node{children: make(map[rune]*node)}
			cur.children[r] = next
		}
		cur = next
	}

	if cur.value != nil {
		t.size--
	}
	if value != nil {
		t.size++
	}
	cur.value = value
}

type queueEntry struct {
	key   string
	value *node
}

// FindSuffixes invokes the Visitor with all key-value pairs where the key is prefixed by `key`,
// including exact matches. It does this in an unspecified order, and terminates early if the
// Visitor returns false.
//
// Invoking FindSuffixes with the empty string as a key will iterate over all values.
func (t *Trie) FindSuffixes(key string, f Visitor) {
	cur := t.root
	for _, r := range key {
		next, ok := cur.children[r]
		if !ok {
			return
		}
		cur = next
	}

	queue := make([]queueEntry, 0)
	queue = append(queue, queueEntry{key: key, value: cur})

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		if cur.value.value != nil && !f(cur.key, cur.value.value) {
			return
		}

		for r, v := range cur.value.children {
			queue = append(queue, queueEntry{key: cur.key + string(r), value: v})
		}
	}
}

// Size returns the total number of values in the Trie.
func (t *Trie) Size() int {
	return t.size
}
