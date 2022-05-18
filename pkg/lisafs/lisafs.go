// Copyright 2021 The gVisor Authors.
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

// Package lisafs (LInux SAndbox FileSystem) defines the protocol for
// filesystem RPCs between an untrusted Sandbox (client) and a trusted
// filesystem server.
//
// Lock ordering:
//
//	Server.renameMu
//	  Node.opMu
//	    Node.childrenMu
//	      Node.controlFDsMu
//
// Locking rules:
//   - Node.childrenMu can be simultaneously held on multiple nodes, ancestors
//     before descendants.
//   - Node.opMu can be simultaneously held on multiple nodes, ancestors before
//     descendants.
//   - Node.opMu can be simultaneously held on two nodes that do not have an
//     ancestor-descendant relationship. One node must be an internal (directory)
//     node and the other a leaf (non-directory) node. Directory must be locked
//     before non-directories.
//   - "Ancestors before descendants" requires that Server.renameMu is locked to
//     ensure that this ordering remains satisfied.
package lisafs
