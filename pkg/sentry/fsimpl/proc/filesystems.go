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

package proc

// filesystemsData implements vfs.DynamicBytesSource for /proc/filesystems.
//
// +stateify savable
type filesystemsData struct{}

// TODO(b/138862512): Implement vfs.DynamicBytesSource.Generate for
// filesystemsData. We would need to retrive filesystem names from
// vfs.VirtualFilesystem. Also needs vfs replacement for
// fs.Filesystem.AllowUserList() and fs.FilesystemRequiresDev.
