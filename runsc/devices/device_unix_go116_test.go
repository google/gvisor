//go:build !go1.17
// +build !go1.17

package devices

import "io/fs"

// The following code is adapted from go1.17.1/src/io/fs/readdir.go
// to compensate for the lack of fs.FileInfoToDirEntry in Go 1.16.

// dirInfo is a DirEntry based on a FileInfo.
type dirInfo struct {
	fileInfo fs.FileInfo
}

func (di dirInfo) IsDir() bool {
	return di.fileInfo.IsDir()
}

func (di dirInfo) Type() fs.FileMode {
	return di.fileInfo.Mode().Type()
}

func (di dirInfo) Info() (fs.FileInfo, error) {
	return di.fileInfo, nil
}

func (di dirInfo) Name() string {
	return di.fileInfo.Name()
}

// fileInfoToDirEntry returns a DirEntry that returns information from info.
// If info is nil, FileInfoToDirEntry returns nil.
func fileInfoToDirEntry(info fs.FileInfo) fs.DirEntry {
	if info == nil {
		return nil
	}
	return dirInfo{fileInfo: info}
}
