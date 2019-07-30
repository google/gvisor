// Copyright 2019 The gVisor Authors.
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

package ext

// directory represents a directory inode. It holds the childList in memory.
type directory struct {
	inode inode

	// childList is a list containing (1) child Dentries and (2) fake Dentries
	// (with inode == nil) that represent the iteration position of
	// directoryFDs. childList is used to support directoryFD.IterDirents()
	// efficiently. childList is immutable.
	childList dentryList

	// TODO(b/134676337): Add directory navigators.
}

// newDirectroy is the directory constructor.
func newDirectroy(inode inode) *directory {
	// TODO(b/134676337): initialize childList.
	file := &directory{inode: inode}
	file.inode.impl = file
	return file
}
