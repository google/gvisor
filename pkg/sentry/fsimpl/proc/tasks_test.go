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

import (
	"fmt"
	"path"
	"strconv"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

type testIterDirentsCallback struct {
	dirents []vfs.Dirent
}

func (t *testIterDirentsCallback) Handle(d vfs.Dirent) bool {
	t.dirents = append(t.dirents, d)
	return true
}

func checkDots(dirs []vfs.Dirent) ([]vfs.Dirent, error) {
	if got := len(dirs); got < 2 {
		return dirs, fmt.Errorf("wrong number of dirents, want at least: 2, got: %d: %v", got, dirs)
	}
	for i, want := range []string{".", ".."} {
		if got := dirs[i].Name; got != want {
			return dirs, fmt.Errorf("wrong name, want: %s, got: %s", want, got)
		}
		if got := dirs[i].Type; got != linux.DT_DIR {
			return dirs, fmt.Errorf("wrong type, want: %d, got: %d", linux.DT_DIR, got)
		}
	}
	return dirs[2:], nil
}

func checkTasksStaticFiles(gots []vfs.Dirent) ([]vfs.Dirent, error) {
	wants := map[string]vfs.Dirent{
		"loadavg":     {Type: linux.DT_REG},
		"meminfo":     {Type: linux.DT_REG},
		"mounts":      {Type: linux.DT_LNK},
		"self":        {Type: linux.DT_LNK},
		"stat":        {Type: linux.DT_REG},
		"thread-self": {Type: linux.DT_LNK},
		"version":     {Type: linux.DT_REG},
	}
	return checkFiles(gots, wants)
}

func checkTaskStaticFiles(gots []vfs.Dirent) ([]vfs.Dirent, error) {
	wants := map[string]vfs.Dirent{
		"io":     {Type: linux.DT_REG},
		"maps":   {Type: linux.DT_REG},
		"smaps":  {Type: linux.DT_REG},
		"stat":   {Type: linux.DT_REG},
		"statm":  {Type: linux.DT_REG},
		"status": {Type: linux.DT_REG},
	}
	return checkFiles(gots, wants)
}

func checkFiles(gots []vfs.Dirent, wants map[string]vfs.Dirent) ([]vfs.Dirent, error) {
	// Go over all files, when there is a match, the file is removed from both
	// 'gots' and 'wants'. wants is expected to reach 0, as all files must
	// be present. Remaining files in 'gots', is returned to caller to decide
	// whether this is valid or not.
	for i := 0; i < len(gots); i++ {
		got := gots[i]
		want, ok := wants[got.Name]
		if !ok {
			continue
		}
		if want.Type != got.Type {
			return gots, fmt.Errorf("wrong file type, want: %v, got: %v: %+v", want.Type, got.Type, got)
		}

		delete(wants, got.Name)
		gots = append(gots[0:i], gots[i+1:]...)
		i--
	}
	if len(wants) != 0 {
		return gots, fmt.Errorf("not all files were found, missing: %+v", wants)
	}
	return gots, nil
}

func setup() (context.Context, *vfs.VirtualFilesystem, vfs.VirtualDentry, error) {
	k, err := boot()
	if err != nil {
		return nil, nil, vfs.VirtualDentry{}, fmt.Errorf("creating kernel: %v", err)
	}

	ctx := k.SupervisorContext()
	creds := auth.CredentialsFromContext(ctx)

	vfsObj := vfs.New()
	vfsObj.MustRegisterFilesystemType("procfs", &procFSType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", "procfs", &vfs.GetFilesystemOptions{})
	if err != nil {
		return nil, nil, vfs.VirtualDentry{}, fmt.Errorf("NewMountNamespace(): %v", err)
	}
	return ctx, vfsObj, mntns.Root(), nil
}

func TestTasksEmpty(t *testing.T) {
	ctx, vfsObj, root, err := setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer root.DecRef()

	fd, err := vfsObj.OpenAt(
		ctx,
		auth.CredentialsFromContext(ctx),
		&vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse("/")},
		&vfs.OpenOptions{},
	)
	if err != nil {
		t.Fatalf("vfsfs.OpenAt failed: %v", err)
	}

	cb := testIterDirentsCallback{}
	if err := fd.Impl().IterDirents(ctx, &cb); err != nil {
		t.Fatalf("IterDirents(): %v", err)
	}
	cb.dirents, err = checkDots(cb.dirents)
	if err != nil {
		t.Error(err.Error())
	}
	cb.dirents, err = checkTasksStaticFiles(cb.dirents)
	if err != nil {
		t.Error(err.Error())
	}
	if len(cb.dirents) != 0 {
		t.Error("found more files than expected: %+v", cb.dirents)
	}
}

func TestTasks(t *testing.T) {
	ctx, vfsObj, root, err := setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer root.DecRef()

	k := kernel.KernelFromContext(ctx)
	var tasks []*kernel.Task
	for i := 0; i < 5; i++ {
		tc := k.NewThreadGroup(nil, k.RootPIDNamespace(), kernel.NewSignalHandlers(), linux.SIGCHLD, k.GlobalInit().Limits())
		task, err := createTask(ctx, fmt.Sprintf("name-%d", i), tc)
		if err != nil {
			t.Fatalf("CreateTask(): %v", err)
		}
		tasks = append(tasks, task)
	}

	fd, err := vfsObj.OpenAt(
		ctx,
		auth.CredentialsFromContext(ctx),
		&vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse("/")},
		&vfs.OpenOptions{},
	)
	if err != nil {
		t.Fatalf("vfsfs.OpenAt(/) failed: %v", err)
	}

	cb := testIterDirentsCallback{}
	if err := fd.Impl().IterDirents(ctx, &cb); err != nil {
		t.Fatalf("IterDirents(): %v", err)
	}
	cb.dirents, err = checkDots(cb.dirents)
	if err != nil {
		t.Error(err.Error())
	}
	cb.dirents, err = checkTasksStaticFiles(cb.dirents)
	if err != nil {
		t.Error(err.Error())
	}
	lastPid := 0
	for _, d := range cb.dirents {
		pid, err := strconv.Atoi(d.Name)
		if err != nil {
			t.Fatalf("Invalid process directory %q", d.Name)
		}
		if lastPid > pid {
			t.Errorf("pids not in order: %v", cb.dirents)
		}
		found := false
		for _, t := range tasks {
			if k.TaskSet().Root.IDOfTask(t) == kernel.ThreadID(pid) {
				found = true
			}
		}
		if !found {
			t.Errorf("Additional task ID %d listed: %v", pid, tasks)
		}
	}

	// Test lookup.
	for _, path := range []string{"/1", "/2"} {
		fd, err := vfsObj.OpenAt(
			ctx,
			auth.CredentialsFromContext(ctx),
			&vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(path)},
			&vfs.OpenOptions{},
		)
		if err != nil {
			t.Fatalf("vfsfs.OpenAt(%q) failed: %v", path, err)
		}
		buf := make([]byte, 1)
		bufIOSeq := usermem.BytesIOSequence(buf)
		if _, err := fd.Read(ctx, bufIOSeq, vfs.ReadOptions{}); err != syserror.EISDIR {
			t.Errorf("wrong error reading directory: %v", err)
		}
	}

	if _, err := vfsObj.OpenAt(
		ctx,
		auth.CredentialsFromContext(ctx),
		&vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse("/9999")},
		&vfs.OpenOptions{},
	); err != syserror.ENOENT {
		t.Fatalf("wrong error from vfsfs.OpenAt(/9999): %v", err)
	}
}

func TestTask(t *testing.T) {
	ctx, vfsObj, root, err := setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer root.DecRef()

	k := kernel.KernelFromContext(ctx)
	tc := k.NewThreadGroup(nil, k.RootPIDNamespace(), kernel.NewSignalHandlers(), linux.SIGCHLD, k.GlobalInit().Limits())
	_, err = createTask(ctx, "name", tc)
	if err != nil {
		t.Fatalf("CreateTask(): %v", err)
	}

	fd, err := vfsObj.OpenAt(
		ctx,
		auth.CredentialsFromContext(ctx),
		&vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse("/1")},
		&vfs.OpenOptions{},
	)
	if err != nil {
		t.Fatalf("vfsfs.OpenAt(/1) failed: %v", err)
	}

	cb := testIterDirentsCallback{}
	if err := fd.Impl().IterDirents(ctx, &cb); err != nil {
		t.Fatalf("IterDirents(): %v", err)
	}
	cb.dirents, err = checkDots(cb.dirents)
	if err != nil {
		t.Error(err.Error())
	}
	cb.dirents, err = checkTaskStaticFiles(cb.dirents)
	if err != nil {
		t.Error(err.Error())
	}
	if len(cb.dirents) != 0 {
		t.Errorf("found more files than expected: %+v", cb.dirents)
	}
}

func TestProcSelf(t *testing.T) {
	ctx, vfsObj, root, err := setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer root.DecRef()

	k := kernel.KernelFromContext(ctx)
	tc := k.NewThreadGroup(nil, k.RootPIDNamespace(), kernel.NewSignalHandlers(), linux.SIGCHLD, k.GlobalInit().Limits())
	task, err := createTask(ctx, "name", tc)
	if err != nil {
		t.Fatalf("CreateTask(): %v", err)
	}

	fd, err := vfsObj.OpenAt(
		task,
		auth.CredentialsFromContext(ctx),
		&vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse("/self/"), FollowFinalSymlink: true},
		&vfs.OpenOptions{},
	)
	if err != nil {
		t.Fatalf("vfsfs.OpenAt(/self/) failed: %v", err)
	}

	cb := testIterDirentsCallback{}
	if err := fd.Impl().IterDirents(ctx, &cb); err != nil {
		t.Fatalf("IterDirents(): %v", err)
	}
	cb.dirents, err = checkDots(cb.dirents)
	if err != nil {
		t.Error(err.Error())
	}
	cb.dirents, err = checkTaskStaticFiles(cb.dirents)
	if err != nil {
		t.Error(err.Error())
	}
	if len(cb.dirents) != 0 {
		t.Errorf("found more files than expected: %+v", cb.dirents)
	}
}

func iterateDir(ctx context.Context, t *testing.T, vfsObj *vfs.VirtualFilesystem, root vfs.VirtualDentry, fd *vfs.FileDescription) {
	t.Logf("Iterating: /proc%s", fd.MappedName(ctx))

	cb := testIterDirentsCallback{}
	if err := fd.Impl().IterDirents(ctx, &cb); err != nil {
		t.Fatalf("IterDirents(): %v", err)
	}
	var err error
	cb.dirents, err = checkDots(cb.dirents)
	if err != nil {
		t.Error(err.Error())
	}
	for _, d := range cb.dirents {
		childPath := path.Join(fd.MappedName(ctx), d.Name)
		if d.Type == linux.DT_LNK {
			link, err := vfsObj.ReadlinkAt(
				ctx,
				auth.CredentialsFromContext(ctx),
				&vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(childPath)},
			)
			if err != nil {
				t.Errorf("vfsfs.ReadlinkAt(%v) failed: %v", childPath, err)
			} else {
				t.Logf("Skipping symlink: /proc%s => %s", childPath, link)
			}
			continue
		}

		t.Logf("Opening: /proc%s", childPath)
		child, err := vfsObj.OpenAt(
			ctx,
			auth.CredentialsFromContext(ctx),
			&vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(childPath)},
			&vfs.OpenOptions{},
		)
		if err != nil {
			t.Errorf("vfsfs.OpenAt(%v) failed: %v", childPath, err)
			continue
		}
		stat, err := child.Stat(ctx, vfs.StatOptions{})
		if err != nil {
			t.Errorf("Stat(%v) failed: %v", childPath, err)
		}
		if got := linux.FileMode(stat.Mode).DirentType(); got != d.Type {
			t.Errorf("wrong file mode, stat: %v, dirent: %v", got, d.Type)
		}
		if d.Type == linux.DT_DIR {
			// Found another dir, let's do it again!
			iterateDir(ctx, t, vfsObj, root, child)
		}
	}
}

// TestTree iterates all directories and stats every file.
func TestTree(t *testing.T) {
	uberCtx, vfsObj, root, err := setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer root.DecRef()

	k := kernel.KernelFromContext(uberCtx)
	var tasks []*kernel.Task
	for i := 0; i < 5; i++ {
		tc := k.NewThreadGroup(nil, k.RootPIDNamespace(), kernel.NewSignalHandlers(), linux.SIGCHLD, k.GlobalInit().Limits())
		task, err := createTask(uberCtx, fmt.Sprintf("name-%d", i), tc)
		if err != nil {
			t.Fatalf("CreateTask(): %v", err)
		}
		tasks = append(tasks, task)
	}

	ctx := tasks[0]
	fd, err := vfsObj.OpenAt(
		ctx,
		auth.CredentialsFromContext(uberCtx),
		&vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse("/")},
		&vfs.OpenOptions{},
	)
	if err != nil {
		t.Fatalf("vfsfs.OpenAt(/) failed: %v", err)
	}
	iterateDir(ctx, t, vfsObj, root, fd)
}
