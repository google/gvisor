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

package vfs

import (
	"testing"

	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

func TestPrefixResolvingPath(t *testing.T) {
	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)
	vfsObj := &VirtualFilesystem{}

	// Verity prefixing an original ResolvingPath yileds correct result.
	path := "/foo/bar"
	pop := &PathOperation{
		Path: fspath.Parse(path),
	}
	rp := vfsObj.getResolvingPath(creds, pop)
	rp.PrefixResolvingPath(".merkle.")

	var prefixedPath string
	for !rp.Done() {
		prefixedPath += "/" + rp.Component()
		rp.Advance()
	}
	vfsObj.putResolvingPath(rp)
	expectedPath := "/foo/.merkle.bar"
	if prefixedPath != expectedPath {
		t.Errorf("prefixedPath got %s, want %s", prefixedPath, expectedPath)
	}

	// Verity prefixing a ResolvingPath that has advanced to the end yields
	// the correct result.
	rp = vfsObj.getResolvingPath(creds, pop)
	for !rp.Done() {
		rp.Advance()
	}
	rp.PrefixResolvingPath(".merkle.")

	prefixedPath = ""
	for !rp.Done() {
		prefixedPath += "/" + rp.Component()
		rp.Advance()
	}
	vfsObj.putResolvingPath(rp)
	if prefixedPath != expectedPath {
		t.Errorf("prefixedPath got %s, want %s", prefixedPath, expectedPath)
	}
}
