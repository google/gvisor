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

// Package checkpointfiles defines constants used when sentry state is
// checkpointed to multiple files in a directory rather than to an opaque FD.
package checkpointfiles

const (
	// StateFileName is the file in an image-path directory which contains the
	// sentry object graph.
	StateFileName = "checkpoint.img"

	// PagesMetadataFileName is the file in an image-path directory containing
	// MemoryFile metadata.
	PagesMetadataFileName = "pages_meta.img"

	// PagesFileName is the file in an image-path directory containing
	// MemoryFile page contents.
	PagesFileName = "pages.img"
)
