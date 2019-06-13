package goext4

import (
	"io"
	"log"
	"path"
)

type directoryWalkQueueItem struct {
	fullDirectoryPath string
	inode             *Inode
	directoryBrowser  *DirectoryBrowser
}

// DirectoryWalk provides full directory-structure recursion.
type DirectoryWalk struct {
	rs                   io.ReadSeeker
	blockGroupDescriptor *BlockGroupDescriptor
	inodeQueue           []directoryWalkQueueItem
}

// NewDirectoryWalk intializes DirectoryWalk for a given root inode.
func NewDirectoryWalk(rs io.ReadSeeker, bgd *BlockGroupDescriptor, rootInodeNumber int) (dw *DirectoryWalk, err error) {
	defer func() {
		if state := recover(); state != nil {
			err = WrapError(state)
		}
	}()

	dw = &DirectoryWalk{
		rs:                   rs,
		blockGroupDescriptor: bgd,
	}

	inode, db, err := dw.openInode(rootInodeNumber)
	if err != nil {
		panic(err)
	}

	dwqi := directoryWalkQueueItem{
		inode:            inode,
		directoryBrowser: db,
	}

	dw.inodeQueue = []directoryWalkQueueItem{dwqi}

	return dw, nil
}

func (dw *DirectoryWalk) openInode(inodeNumber int) (inode *Inode, db *DirectoryBrowser, err error) {
	defer func() {
		if state := recover(); state != nil {
			err = WrapError(state)
		}
	}()

	inode, err = NewInodeWithReadSeeker(dw.blockGroupDescriptor, dw.rs, inodeNumber)
	if err != nil {
		panic(err)
	}

	db = NewDirectoryBrowser(dw.rs, inode)

	return inode, db, nil
}

// Next steps through the entire tree starting at the given root inode, one
// entry at a time. We guarantee that all adjacent entries will be processed
// adjacently. This will not return the "." and ".." entries.
func (dw *DirectoryWalk) Next() (fullPath string, de *DirectoryEntry, err error) {
	defer func() {
		if state := recover(); state != nil {
			err = WrapError(state)
		}
	}()

	for {
		if len(dw.inodeQueue) == 0 {
			return "", nil, io.EOF
		}

		// Keep popping entries off the current directory until we've read
		// everything.
		dwqi := dw.inodeQueue[0]

		de, err := dwqi.directoryBrowser.Next()
		if err == io.EOF {
			// No more entries.

			dw.inodeQueue = dw.inodeQueue[1:]
			continue
		} else if err != nil {
			log.Panic(err)
		}

		// There was at least one more entry.

		filename := de.Name()

		// Skip the special files. We have a handle on things and they're not
		// especially useful since they don't actually contain the directory
		// names.
		if filename == "." || filename == ".." {
			continue
		}

		var fullFilepath string
		if dwqi.fullDirectoryPath == "" {
			fullFilepath = filename
		} else {
			fullFilepath = path.Join(dwqi.fullDirectoryPath, filename)
		}

		// If it's a directory, enqueue it).
		// TODO(dustin): We get the impression that the "lost+found" inode isn't necessarily always in inode (11), so we only do a string match. Use `(superblock).SLpfIno` instead.
		// TODO(dustin): "lost+found" produces some empty entries for our tiny, mostly untouched, mostly vanilla test image, which doesn't make sense to us. Just skipping for now. Revisit.
		if de.IsDirectory() && filename != "lost+found" {
			childInode, childDb, err := dw.openInode(int(de.data.Inode))
			if err != nil {
				panic(err)
			}

			newDwqi := directoryWalkQueueItem{
				fullDirectoryPath: fullFilepath,
				inode:             childInode,
				directoryBrowser:  childDb,
			}

			dw.inodeQueue = append(dw.inodeQueue, newDwqi)
		}

		return fullFilepath, de, nil
	}
}
