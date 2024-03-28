// Copyright 2024 The gVisor Authors.
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

package testutil

import (
	"sort"
	"strings"
	"testing"
)

// Tree represents a hierarchy of tests and sub-tests.
// It is a nested structure built out of a flat list of fully-qualified
// test names, and can then execute them using nested `t.Run`s.
// It is useful to run a series of hierarchical Go tests in cases where
// the hierarchy is not known at test compilation time.
type Tree struct {
	root *treeNode
}

// treeNode represents a hierarchy of tests and sub-tests.
type treeNode struct {
	// testName is only set on leaf nodes.
	// It is a fully-qualified test name.
	testName string

	// children is only set of non-leaf nodes.
	// It is a set of child nodes, mapped by their component as key.
	children map[string]*treeNode
}

// NewTree creates a new test tree out of the given test names.
// Each test name is split by `separator`, which indicates nesting.
// Only leaf nodes are considered actual tests.
// For example: `NewTree([]string{"a/b", "a/c", "a/c/d"}, "/")`
// contains two tests: `a/b` and `a/c/d`.
func NewTree(testNames []string, separator string) *Tree {
	tree := &Tree{root: &treeNode{}}
	for _, testName := range testNames {
		n := tree.root
		for _, component := range strings.Split(testName, separator) {
			if component == "" {
				continue
			}
			child, found := n.children[component]
			if !found {
				child = &treeNode{}
				if n.children == nil {
					n.children = make(map[string]*treeNode)
				}
				n.children[component] = child
			}
			n = child
		}
		n.testName = testName
	}
	return tree
}

// run calls `t.Run` on each test, preserving hierarchy.
// `fn` is called on each leaf node with the fully-qualified test name as
// argument.
func (n *treeNode) run(t *testing.T, parallel bool, fn func(t *testing.T, testName string)) {
	t.Helper()
	if len(n.children) == 0 { // Leaf node.
		fn(t, n.testName)
		return
	}
	childNames := make([]string, 0, len(n.children))
	for childName := range n.children {
		childNames = append(childNames, childName)
	}
	sort.Strings(childNames)
	for _, childName := range childNames {
		childNode := n.children[childName]
		t.Run(childName, func(t *testing.T) {
			if parallel {
				t.Parallel()
			}
			childNode.run(t, parallel, fn)
		})
	}
}

// Run calls `t.Run` on each leaf test, preserving test hierarchy.
// `fn` is called on each leaf node with the fully-qualified test name as
// argument.
func (tree *Tree) Run(t *testing.T, fn func(t *testing.T, testName string)) {
	t.Helper()
	tree.root.run(t, false, fn)
}

// RunParallel calls `t.Run` on each test in parallel, preserving hierarchy.
// `fn` is called on each leaf node with the fully-qualified test name as
// argument.
// `fn` does not need to call `t.Parallel`.
func (tree *Tree) RunParallel(t *testing.T, fn func(t *testing.T, testName string)) {
	t.Helper()
	tree.root.run(t, true, fn)
}
