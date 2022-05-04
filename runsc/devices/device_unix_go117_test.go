//go:build go1.17
// +build go1.17

package devices

import "io/fs"

var fileInfoToDirEntry = fs.FileInfoToDirEntry
