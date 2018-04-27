// Copyright 2018 Google Inc.
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

package fs

// SyncType enumerates ways in which a File can be synced.
type SyncType int

const (
	// SyncAll indicates that modified in-memory metadata and data should
	// be written to backing storage. SyncAll implies SyncBackingStorage.
	SyncAll SyncType = iota

	// SyncData indicates that along with modified in-memory data, only
	// metadata needed to access that data needs to be written.
	//
	// For example, changes to access time or modification time do not
	// need to be written because they are not necessary for a data read
	// to be handled correctly, unlike the file size.
	//
	// The aim of SyncData is to reduce disk activity for applications
	// that do not require all metadata to be synchronized with the disk,
	// see fdatasync(2). File systems that implement SyncData as SyncAll
	// do not support this optimization.
	//
	// SyncData implies SyncBackingStorage.
	SyncData

	// SyncBackingStorage indicates that in-flight write operations to
	// backing storage should be flushed.
	SyncBackingStorage
)
