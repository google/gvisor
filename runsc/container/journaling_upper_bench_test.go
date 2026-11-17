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

package container

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cgi"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/control/controlapi"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs/journal"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

var (
	testPlatforms   = flag.String("test_platforms", "systrap", "Platforms to test with.")
	gitCloneRepoURL = flag.String("git_clone_repo_url", "https://github.com/llvm/llvm-project.git", "Git repository URL to clone once onto the host when --git_clone_bare_dir is unset.")
	gitCloneBareDir = flag.String("git_clone_bare_dir", "", "Optional path to a pre-cloned bare Git repository on the host to serve over HTTP.")
	gitCloneWorkDir = flag.String("git_clone_workdir", "", "Optional host directory for per-iteration container rootfs and filestores.")
)

const (
	// Header offsets and flags from pkg/sentry/fsimpl/tmpfs/journal.
	journalHeaderSize    = 4096
	journalActiveOff     = 24
	journalBrokenBit     = uint64(1) << 63
	journalIncompleteBit = uint64(1) << 62
	// A fresh journal starts at generation 1 and writes one empty mount-time
	// snapshot (generation 2) before container tasks run.
	journalInitialGen = 2
)

func TestMain(m *testing.M) {
	config.RegisterFlags(flag.CommandLine)
	log.SetLevel(log.Warning)
	if err := specutils.MaybeRunAsRoot(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running as root: %v\n", err)
		os.Exit(123)
	}
	os.Exit(m.Run())
}

type gitRepoStats struct {
	bareDir    string
	cloneURL   string
	gitBin     string
	files      int64
	totalBytes int64
}

func findGitBinaries(tb testing.TB) (string, string) {
	tb.Helper()
	gitBin, err := exec.LookPath("git")
	if err != nil {
		tb.Skipf("git binary not found on host: %v", err)
	}
	out, err := exec.Command(gitBin, "--exec-path").Output()
	if err == nil {
		cand := filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")
		if st, statErr := os.Stat(cand); statErr == nil && !st.IsDir() {
			return gitBin, cand
		}
	}
	const fallback = "/usr/lib/git-core/git-http-backend"
	if st, err := os.Stat(fallback); err == nil && !st.IsDir() {
		return gitBin, fallback
	}
	tb.Skip("git-http-backend not found on host")
	return "", ""
}

func startGitHTTPServer(tb testing.TB, gitBin, backendPath, bareDir string) *gitRepoStats {
	tb.Helper()
	handler := &cgi.Handler{
		Path: backendPath,
		Env: []string{
			"GIT_PROJECT_ROOT=" + filepath.Dir(bareDir),
			"GIT_HTTP_EXPORT_ALL=1",
			"GIT_CONFIG_COUNT=2",
			"GIT_CONFIG_KEY_0=safe.bareRepository",
			"GIT_CONFIG_VALUE_0=all",
			"GIT_CONFIG_KEY_1=http.uploadpack",
			"GIT_CONFIG_VALUE_1=true",
		},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("net.Listen: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go srv.Serve(ln)
	tb.Cleanup(func() { srv.Close() })

	files, worktreeBytes := countGitTree(tb, gitBin, bareDir)
	packBytes := dirBytes(filepath.Join(bareDir, "objects"))
	return &gitRepoStats{
		bareDir:    bareDir,
		cloneURL:   fmt.Sprintf("http://%s/%s", ln.Addr().String(), filepath.Base(bareDir)),
		gitBin:     gitBin,
		files:      files,
		totalBytes: worktreeBytes + packBytes,
	}
}

func countGitTree(tb testing.TB, gitBin, bareDir string) (int64, int64) {
	tb.Helper()
	cmd := exec.Command(gitBin, "-c", "safe.bareRepository=all", "--git-dir="+bareDir, "ls-tree", "-r", "-l", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		tb.Fatalf("git ls-tree: %v", err)
	}
	var files, total int64
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		meta, _, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		fields := strings.Fields(meta)
		if len(fields) < 4 || fields[1] != "blob" {
			continue
		}
		sz, err := strconv.ParseInt(fields[3], 10, 64)
		if err != nil {
			continue
		}
		files++
		total += sz
	}
	return files, total
}

func dirBytes(root string) int64 {
	var total int64
	_ = filepath.WalkDir(root, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, infoErr := d.Info(); infoErr == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

func prepareBenchmarkGitRepo(b *testing.B) *gitRepoStats {
	b.Helper()
	gitBin, backendPath := findGitBinaries(b)
	bareDir := *gitCloneBareDir
	if bareDir == "" {
		parent := *gitCloneWorkDir
		if parent == "" {
			parent = b.TempDir()
		}
		tmpParent, err := os.MkdirTemp(parent, "git-bare-")
		if err != nil {
			b.Fatalf("MkdirTemp: %v", err)
		}
		b.Cleanup(func() { os.RemoveAll(tmpParent) })
		bareDir = filepath.Join(tmpParent, "repo.git")
		cmd := exec.Command(gitBin, "clone", "--bare", "--depth=1", *gitCloneRepoURL, bareDir)
		if out, err := cmd.CombinedOutput(); err != nil {
			b.Fatalf("git clone --bare %q: %v\n%s", *gitCloneRepoURL, err, out)
		}
	}
	return startGitHTTPServer(b, gitBin, backendPath, bareDir)
}

func prepareSyntheticGitRepo(t *testing.T, numFiles int) *gitRepoStats {
	t.Helper()
	gitBin, backendPath := findGitBinaries(t)
	tmp := t.TempDir()
	srcDir := filepath.Join(tmp, "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	runGit := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command(gitBin, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test",
			"GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=test",
			"GIT_COMMITTER_EMAIL=test@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	runGit(srcDir, "init", "-q")
	payload := bytes.Repeat([]byte("gvisor-journal-bench\n"), 64)
	for i := 0; i < numFiles; i++ {
		sub := filepath.Join(srcDir, fmt.Sprintf("pkg%02d", i%8))
		if err := os.MkdirAll(sub, 0755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(filepath.Join(sub, fmt.Sprintf("file_%04d.txt", i)), payload, 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	runGit(srcDir, "add", ".")
	runGit(srcDir, "commit", "-q", "-m", "initial")

	bareDir := filepath.Join(tmp, "synthetic.git")
	runGit(tmp, "clone", "--quiet", "--bare", srcDir, bareDir)
	return startGitHTTPServer(t, gitBin, backendPath, bareDir)
}

func makeGitCloneRootfs(tb testing.TB, parentDir string) (string, []specs.Mount) {
	tb.Helper()
	rootPath, err := os.MkdirTemp(parentDir, "rootfs-")
	if err != nil {
		tb.Fatalf("MkdirTemp(rootfs): %v", err)
	}
	for _, d := range []string{"etc", "root", "work"} {
		if err := os.MkdirAll(filepath.Join(rootPath, d), 0755); err != nil {
			tb.Fatalf("MkdirAll(%q): %v", d, err)
		}
	}
	if err := os.WriteFile(filepath.Join(rootPath, "etc", "hosts"), []byte("127.0.0.1 localhost\n"), 0644); err != nil {
		tb.Fatalf("WriteFile(hosts): %v", err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "etc", "nsswitch.conf"), []byte("hosts: files\n"), 0644); err != nil {
		tb.Fatalf("WriteFile(nsswitch.conf): %v", err)
	}
	var mounts []specs.Mount
	for _, sysDir := range []string{"/bin", "/usr", "/lib", "/lib64", "/etc/alternatives"} {
		fi, err := os.Stat(sysDir)
		if err != nil || !fi.IsDir() {
			continue
		}
		dst := filepath.Join(rootPath, strings.TrimPrefix(sysDir, "/"))
		if err := os.MkdirAll(dst, 0755); err != nil {
			tb.Fatalf("MkdirAll(%q): %v", dst, err)
		}
		mounts = append(mounts, specs.Mount{
			Type:        "bind",
			Destination: sysDir,
			Source:      sysDir,
			Options:     []string{"rbind", "ro"},
		})
	}
	return rootPath, mounts
}

func execInContainer(conf *config.Config, cont *Container, env []string, bin string, argv ...string) error {
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	defer r.Close()

	args := &controlapi.ExecArgs{
		Filename:         bin,
		Argv:             append([]string{bin}, argv...),
		Envv:             env,
		WorkingDirectory: "/",
		FilePayload: controlapi.NewFilePayload(map[int]*os.File{
			0: os.Stdin,
			1: w,
			2: w,
		}, nil),
	}
	pid, err := cont.Execute(conf, args)
	w.Close()
	if err != nil {
		return fmt.Errorf("Execute: %w", err)
	}
	outCh := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(r)
		outCh <- b
	}()
	ws, err := cont.WaitPID(pid)
	out := <-outCh
	if err != nil {
		return fmt.Errorf("WaitPID: %w (output: %s)", err, out)
	}
	if !ws.Exited() || ws.ExitStatus() != 0 {
		return fmt.Errorf("command %v exited with status %v: %s", argv, ws, out)
	}
	return nil
}

func waitFilestoreUnlocked(tb testing.TB, path string) {
	tb.Helper()
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		tb.Fatalf("Open(%q): %v", path, err)
	}
	defer f.Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
			return
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			tb.Fatalf("Flock(%q): %v", path, err)
		}
		if time.Now().After(deadline) {
			tb.Fatalf("timed out waiting for flock release on %q", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func readJournalCompactions(tb testing.TB, filestorePath string) uint64 {
	tb.Helper()
	f, err := os.Open(filestorePath + specutils.JournalFileSuffix)
	if err != nil {
		tb.Fatalf("Open(%q): %v", filestorePath, err)
	}
	defer f.Close()

	if _, ok, err := journal.FilestoreEnd(f); err != nil || !ok {
		tb.Fatalf("FilestoreEnd(%q): ok=%t, err=%v", filestorePath, ok, err)
	}
	var hdr [journalHeaderSize]byte
	if _, err := f.ReadAt(hdr[:], 0); err != nil {
		tb.Fatalf("ReadAt(%q): %v", filestorePath, err)
	}
	active := binary.LittleEndian.Uint64(hdr[journalActiveOff:])
	if active&(journalBrokenBit|journalIncompleteBit) != 0 {
		tb.Fatalf("journal header in %q has error flags set: active=%#x", filestorePath, active)
	}
	if active < journalInitialGen {
		return 0
	}
	return active - journalInitialGen
}

func runGitCloneIteration(tb testing.TB, baseConf *config.Config, repo *gitRepoStats, parentDir string, measure func(func())) uint64 {
	tb.Helper()
	iterDir, err := os.MkdirTemp(parentDir, "clone-iter-")
	if err != nil {
		tb.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(iterDir)

	conf := *baseConf
	rootPath, sysMounts := makeGitCloneRootfs(tb, iterDir)
	spec := testutil.NewSpecWithArgs("/bin/sleep", "10000")
	spec.Root = &specs.Root{Path: rootPath, Readonly: false}
	// Replace testutil.NewSpecWithArgs's host /tmp bind mount so all temporary
	// packfiles and checked-out files land on the rootfs overlay upper tmpfs.
	spec.Mounts = append([]specs.Mount{
		{Type: "tmpfs", Destination: "/dev"},
	}, sysMounts...)
	if spec.Linux != nil {
		var filtered []specs.LinuxNamespace
		for _, ns := range spec.Linux.Namespaces {
			if ns.Type != specs.NetworkNamespace {
				filtered = append(filtered, ns)
			}
		}
		spec.Linux.Namespaces = filtered
	}

	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, &conf)
	if err != nil {
		tb.Fatalf("SetupContainer: %v", err)
	}
	defer cleanup()

	cont, err := New(&conf, Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	})
	if err != nil {
		tb.Fatalf("New: %v", err)
	}
	filestorePath := sentryapi.SelfFilestorePath(rootPath, cont.Saver.ID.SandboxID)
	destroyed := false
	defer func() {
		if !destroyed {
			_ = cont.Destroy()
		}
	}()

	if err := cont.Start(&conf); err != nil {
		tb.Fatalf("Start: %v", err)
	}

	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=/root",
		"TMPDIR=/work",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
	}
	var cloneErr error
	measure(func() {
		cloneErr = execInContainer(&conf, cont, env, repo.gitBin, "clone", "--quiet", "--depth=1", repo.cloneURL, "/work/repo")
	})
	if cloneErr != nil {
		tb.Fatalf("git clone inside container failed: %v", cloneErr)
	}

	destroyed = true
	if err := cont.Destroy(); err != nil {
		tb.Fatalf("Destroy: %v", err)
	}
	if conf.JournalingRootfsUpper == config.JournalingRootfsUpperOn {
		waitFilestoreUnlocked(tb, filestorePath)
		return readJournalCompactions(tb, filestorePath)
	}
	return 0
}

// BenchmarkJournalingUpperGitClone benchmarks cloning a Git repository over
// HTTP into a file-backed rootfs overlay upper tmpfs with journaling disabled
// versus enabled (including background journal compaction pauses).
func BenchmarkJournalingUpperGitClone(b *testing.B) {
	if err := testutil.ConfigureExePath(); err != nil {
		b.Fatalf("ConfigureExePath: %v", err)
	}
	repo := prepareBenchmarkGitRepo(b)
	workParent := *gitCloneWorkDir
	if workParent == "" {
		workParent = b.TempDir()
	}
	sharedRoot, err := os.MkdirTemp(workParent, "shared-root-")
	if err != nil {
		b.Fatalf("MkdirTemp(shared-root): %v", err)
	}
	b.Cleanup(func() {
		specutils.UnmountNullNetNS(sharedRoot)
		os.RemoveAll(sharedRoot)
	})

	platforms := testutil.PlatformConfigs(b, *testPlatforms, func() *config.Config {
		conf := testutil.ConfigForBenchmark(b)
		conf.SharedRootDir = sharedRoot
		if unix.Access("/sys/kernel/mm/transparent_hugepage/shmem_enabled", unix.W_OK) != nil {
			conf.HostSettings = config.HostSettingsIgnore
		}
		return conf
	})
	for _, pc := range platforms {
		if !pc.Conf.Overlay2.Enabled() {
			continue
		}
		for _, journaled := range []bool{false, true} {
			name := fmt.Sprintf("%s/journaling=%t", strings.TrimSuffix(pc.Name, "_overlay"), journaled)
			b.Run(name, func(b *testing.B) {
				conf := *pc.Conf
				conf.Network = config.NetworkHost
				if journaled {
					conf.JournalingRootfsUpper = config.JournalingRootfsUpperOn
				} else {
					conf.JournalingRootfsUpper = config.JournalingRootfsUpperOff
				}

				b.SetBytes(repo.totalBytes)
				b.StopTimer()
				b.ResetTimer()

				var totalCompactions uint64
				var totalElapsed time.Duration
				for i := 0; i < b.N; i++ {
					var iterElapsed time.Duration
					compactions := runGitCloneIteration(b, &conf, repo, workParent, func(fn func()) {
						iterElapsed = testutil.Measure(b, fn)
					})
					totalCompactions += compactions
					totalElapsed += iterElapsed
				}
				if b.N > 0 && totalElapsed > 0 {
					b.ReportMetric(float64(totalCompactions)/float64(b.N), "compactions/op")
					b.ReportMetric(float64(repo.files)*float64(b.N)/totalElapsed.Seconds(), "files/s")
				}
			})
		}
	}
}

func TestJournalingUpperGitCloneBenchmark(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("ConfigureExePath: %v", err)
	}
	// 120 files with a 16 KiB minimum region size exercises multiple background
	// compactions in under two seconds without external network access.
	repo := prepareSyntheticGitRepo(t, 120)
	parentDir := t.TempDir()

	for _, journaled := range []bool{false, true} {
		t.Run(fmt.Sprintf("journaling=%t", journaled), func(t *testing.T) {
			conf := testutil.TestConfig(t)
			conf.Debug = false
			conf.Strace = false
			conf.LogPackets = false
			if err := conf.Overlay2.Set("root:self"); err != nil {
				t.Fatalf("Overlay2.Set: %v", err)
			}
			conf.Network = config.NetworkHost
			conf.TestOnlyJournalingRootfsUpperRegionSize = 16 << 10
			if journaled {
				conf.JournalingRootfsUpper = config.JournalingRootfsUpperOn
			} else {
				conf.JournalingRootfsUpper = config.JournalingRootfsUpperOff
			}

			compactions := runGitCloneIteration(t, conf, repo, parentDir, func(fn func()) { fn() })
			if journaled && compactions == 0 {
				t.Fatalf("expected runtime compactions > 0 with 16 KiB region, got 0")
			}
			if !journaled && compactions != 0 {
				t.Fatalf("expected 0 compactions when journaling is off, got %d", compactions)
			}
		})
	}
}
