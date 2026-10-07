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

// Moby test runner runs Moby integration tests inside docker container.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gvisor.dev/gvisor/test/runtimes/proctor"
	"gvisor.dev/gvisor/test/runtimes/proctor/lib"
)

// Runner implements proctor's TestRunner interface.
type Runner struct {
	// daemon manages the parent dockerd process shared across tests in a batch.
	daemon *dockerdHandler
	// logFiles holds open per-test log files to close during cleanup.
	logFiles []*os.File
}

// run initializes the Moby test runner and executes the proctor harness.
func run() error {
	r := &Runner{}
	defer r.cleanup()
	return proctor.Run(map[string]lib.TestRunner{
		"moby": r,
	})
}

func main() {
	if err := run(); err != nil {
		slog.Error("moby runner failed", "err", err)
		os.Exit(1)
	}
}

const (
	mobyDir       = "/moby"
	dockerDataDir = "/tmp/docker-data"
	testsTmpDir   = "/tmp/t"
	artifactsDir  = "/proctor-artifacts"
)

// bundledImages are pre-bundled image tarballs to load into dockerd.
// These images are required by some of the tests.
var bundledImages = [...]string{
	"/docker-images/hello-world.tar",
	"/docker-images/busybox.tar",
}

// ListTests implements TestRunner.ListTests.
func (*Runner) ListTests() ([]string, error) {
	testFiles := strings.Fields(os.Getenv("GVISOR_MOBY_TEST_FILES"))
	if len(testFiles) == 0 {
		return nil, fmt.Errorf("GVISOR_MOBY_TEST_FILES environment variable is not set")
	}

	var tests []string
	fset := token.NewFileSet()

	// Parse each test file and extract the test function names.
	for _, file := range testFiles {
		relPath := strings.TrimSuffix(file, ".go")

		node, err := parser.ParseFile(fset, filepath.Join(mobyDir, file), nil, 0)
		if err != nil {
			return nil, err
		}

		for _, decl := range node.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if strings.HasPrefix(fn.Name.Name, "Test") && fn.Name.Name != "TestMain" {
				tests = append(tests, relPath+"/"+fn.Name.Name)
			}
		}
	}

	return tests, nil
}

// TestCmds implements TestRunner.TestCmds.
func (r *Runner) TestCmds(tests []string) []*exec.Cmd {
	if len(tests) == 0 {
		return nil
	}
	if err := r.setup(); err != nil {
		slog.Error("failed to setup runner", "err", err)
		os.Exit(1)
	}

	cmds := make([]*exec.Cmd, 0, len(tests))
	for _, test := range tests {
		cmd, err := r.testCmd(test)
		if err != nil {
			slog.Error("failed to prepare test", "test", test, "err", err)
			os.Exit(1)
		}
		cmds = append(cmds, cmd)
	}
	return cmds
}

// checkEnvironment verifies that required features for
// the Moby integration tests are enabled.
func checkEnvironment() error {
	if out, err := exec.Command("nft", "list", "tables").CombinedOutput(); err != nil {
		return fmt.Errorf("nftables not available(runsc flag --TESTONLY-nftables); err: %w, output: %s", err, string(out))
	}
	rawFD, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return fmt.Errorf("raw IP sockets not supported(runsc flag --net-raw); err: %w", err)
	}
	syscall.Close(rawFD)

	pktFD, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0)
	if err != nil {
		return fmt.Errorf("AF_PACKET sockets not supported (runsc flag --net-raw?); err: %w", err)
	}
	defer syscall.Close(pktFD)
	if err := syscall.Sendto(pktFD, make([]byte, 14), 0, &syscall.SockaddrLinklayer{Ifindex: 1, Halen: 6}); err != nil {
		return fmt.Errorf("AF_PACKET socket writes not supported (runsc flag --allow-packet-socket-write); err: %w", err)
	}
	return nil
}

// setup verifies the container environment, creates the artifacts directory,
// and starts the parent dockerd daemon.
func (r *Runner) setup() error {
	if err := checkEnvironment(); err != nil {
		return err
	}
	// Mount tmpfs on /tmp because overlayfs cannot be used as an upperdir for
	// nested overlay mounts.
	if err := syscall.Mount("tmpfs", "/tmp", "tmpfs", 0, ""); err != nil {
		return fmt.Errorf("failed to mount tmpfs on /tmp: %w", err)
	}
	if err := os.MkdirAll(artifactsDir, 0755); err != nil {
		return fmt.Errorf("failed to create artifacts dir %s: %w", artifactsDir, err)
	}
	daemon, err := startDockerd()
	if err != nil {
		return fmt.Errorf("failed to start dockerd: %w", err)
	}
	r.daemon = daemon
	return nil
}

// testCmd returns a command to run a single test from the pre-compiled test binary.
func (r *Runner) testCmd(test string) (*exec.Cmd, error) {
	// Get test name.
	tn := filepath.Base(test)
	// Setup tmp dir for test logs.
	tmpDir := filepath.Join(testsTmpDir, tn)
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create test tmp dir %s: %w", tmpDir, err)
	}
	logFile, err := os.Create(filepath.Join(tmpDir, "test.log"))
	if err != nil {
		return nil, fmt.Errorf("failed to create test.log: %w", err)
	}
	r.logFiles = append(r.logFiles, logFile)

	pkgDir := filepath.Join(mobyDir, filepath.Dir(filepath.Dir(test)))
	testBin := "./" + filepath.Base(pkgDir) + ".test"
	cmd := exec.Command(testBin, "-test.v", "-test.run", "^"+tn+"$")
	cmd.Dir = pkgDir
	cmd.Env = append(
		os.Environ(),
		"TMPDIR="+tmpDir,
		"DOCKER_INTEGRATION_DAEMON_DEST="+testsTmpDir,
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	return cmd, nil
}

// cleanup copies logs and stops the parent dockerd.
func (r *Runner) cleanup() {
	for _, f := range r.logFiles {
		if err := f.Close(); err != nil {
			slog.Warn("failed to close log file", "file", f.Name(), "err", err)
		}
	}
	if r.daemon == nil {
		return
	}
	copyLogs(testsTmpDir, artifactsDir)
	if err := os.RemoveAll(testsTmpDir); err != nil {
		slog.Warn("failed to remove dir", "dir", testsTmpDir, "err", err)
	}
	r.daemon.cleanup()
}

// dockerdHandler manages the parent dockerd process.
type dockerdHandler struct {
	// logFile to write dockerd stdout and stderr.
	logFile *os.File
	// cmd is the running dockerd command.
	cmd *exec.Cmd
	// exited channel receives the result of cmd.Wait().
	exited chan error
}

// startDockerd starts the parent dockerd process and waits until it is ready.
func startDockerd() (*dockerdHandler, error) {
	d := &dockerdHandler{}
	if err := d.setup(); err != nil {
		d.cleanup()
		return nil, err
	}
	return d, nil
}

// setup initializes the data directory, starts dockerd and loads bundled images.
func (d *dockerdHandler) setup() error {
	if err := os.MkdirAll(dockerDataDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", dockerDataDir, err)
	}

	logFile, err := os.CreateTemp(artifactsDir, "dockerd-*.log")
	if err != nil {
		return fmt.Errorf("failed to create dockerd log: %w", err)
	}
	if err := logFile.Chmod(0644); err != nil {
		logFile.Close()
		return fmt.Errorf("failed to chmod dockerd log: %w", err)
	}
	d.logFile = logFile

	// Set --data-root to /tmp (tmpfs) because overlay2 requires a tmpfs upperdir.
	// TODO: b/568428174 - Remove `-b none` when fixed.
	cmd := exec.Command("dockerd", "--data-root", dockerDataDir, "-b", "none", "-D")
	cmd.Stdout = d.logFile
	cmd.Stderr = d.logFile
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start dockerd: %w", err)
	}
	d.cmd = cmd
	d.exited = make(chan error, 1)
	go func() {
		d.exited <- cmd.Wait()
	}()

	if err := d.waitReady(); err != nil {
		return err
	}
	return d.loadBundledImages()
}

// cleanup stops the dockerd process.
func (d *dockerdHandler) cleanup() {
	if d.cmd != nil && d.cmd.Process != nil {
		if err := d.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			slog.Warn("failed to send SIGTERM to dockerd", "err", err)
		}
		select {
		case <-d.exited:
		case <-time.After(10 * time.Second):
			if err := d.cmd.Process.Kill(); err != nil {
				slog.Warn("failed to kill dockerd", "err", err)
			}
			<-d.exited
		}
	}
	if d.logFile != nil {
		if err := d.logFile.Close(); err != nil {
			slog.Warn("failed to close dockerd log file", "err", err)
		}
	}
	if err := os.RemoveAll(dockerDataDir); err != nil {
		slog.Warn("failed to remove dir", "dir", dockerDataDir, "err", err)
	}
}

// waitReady waits for the dockerd daemon to be ready.
func (d *dockerdHandler) waitReady() error {
	for i := 0; i < 30; i++ {
		select {
		case err := <-d.exited:
			d.exited <- err
			return fmt.Errorf("dockerd exited early, err: %w", err)
		default:
		}

		if err := exec.Command("docker", "info").Run(); err == nil {
			return nil
		}
		time.Sleep(1 * time.Second)
	}

	return fmt.Errorf("timeout waiting for dockerd")
}

// loadBundledImages loads pre-bundled image tarballs into the running dockerd.
func (d *dockerdHandler) loadBundledImages() error {
	for _, imgTar := range bundledImages {
		loadCmd := exec.Command("docker", "load", "-i", imgTar)
		loadCmd.Stdout = os.Stdout
		loadCmd.Stderr = os.Stderr
		if err := loadCmd.Run(); err != nil {
			return fmt.Errorf("failed to load image %s: %w", imgTar, err)
		}
	}
	return nil
}

// copyLogs copies all *.log files from srcDir to dstDir.
func copyLogs(srcDir, dstDir string) {
	if err := filepath.WalkDir(srcDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			slog.Warn("failed to walk path", "path", path, "err", err)
			return nil
		}
		if d.IsDir() || filepath.Ext(path) != ".log" {
			return nil
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			slog.Warn("failed to compute relative path", "path", path, "err", err)
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			slog.Warn("failed to read log", "path", path, "err", err)
			return nil
		}
		dst := filepath.Join(dstDir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			slog.Warn("failed to create log dir", "dir", filepath.Dir(dst), "err", err)
			return nil
		}
		if err := os.WriteFile(dst, data, 0644); err != nil {
			slog.Warn("failed to write log", "path", dst, "err", err)
		}
		return nil
	}); err != nil {
		slog.Warn("failed to copy logs", "src", srcDir, "dst", dstDir, "err", err)
	}
}
