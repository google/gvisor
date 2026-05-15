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

package gofer

import "slices"

// xattrOverlayOpaque is the name of the overlayfs opaque xattr. Note that
// gofer does not support the trusted xattr namespace.
const xattrOverlayOpaque = "user.overlay.opaque"

type xattrCache struct {
	// values caches existing extended attributes.
	values map[string]string

	// negatives tracks xattrs known not to exist (linuxerr.ENODATA).
	negatives map[string]struct{}

	// overlayOpaqueNegative tracks if "user.overlay.opaque" is known not to
	// exist (linuxerr.ENODATA). This avoids allocating xattrsNegative map in
	// the common case.
	overlayOpaqueNegative bool

	// list caches the full list of xattr names. If nil, the list is not cached.
	// If non-nil but empty, the cache is authoritatively empty.
	list []string
}

func (c *xattrCache) get(name string) (val string, negative bool, found bool) {
	if cachedVal, ok := c.values[name]; ok {
		found = true
		val = cachedVal
		return
	}
	if name == xattrOverlayOpaque && c.overlayOpaqueNegative {
		found = true
		negative = true
		return
	}
	if _, ok := c.negatives[name]; ok {
		found = true
		negative = true
		return
	}
	return
}

func (c *xattrCache) add(name string, value string) {
	if c.values == nil {
		c.values = make(map[string]string)
	}
	c.values[name] = value
	if name == xattrOverlayOpaque {
		c.overlayOpaqueNegative = false
	}
	delete(c.negatives, name)
	if c.list != nil {
		if !slices.Contains(c.list, name) {
			c.list = append(c.list, name)
		}
	}
}

func (c *xattrCache) addNegative(name string) {
	delete(c.values, name)
	if name == xattrOverlayOpaque {
		c.overlayOpaqueNegative = true
	} else {
		if c.negatives == nil {
			c.negatives = make(map[string]struct{})
		}
		c.negatives[name] = struct{}{}
	}
	if c.list != nil {
		c.list = slices.DeleteFunc(c.list, func(n string) bool { return n == name })
	}
}

func (c *xattrCache) getList() ([]string, bool) {
	if c.list == nil {
		return nil, false
	}
	// Return a copy to prevent the caller from modifying the cached list.
	return append([]string(nil), c.list...), true
}

func (c *xattrCache) setList(names []string) {
	if len(names) == 0 {
		c.list = []string{}
	} else {
		// Save a copy to prevent the caller from modifying the cached list.
		c.list = append([]string(nil), names...)
	}
}
