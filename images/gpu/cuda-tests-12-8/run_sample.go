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

// run_sample runs a CUDA sample test.
// These tests are complicated because some of them involve X windows,
// as opposed to traditional command-line-only tests.
// This binary handles all types of CUDA sample tests.
//
// To run: /run_sample [--timeout=15m] test1 test2 test3 ...
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Flags.
var (
	timeoutFlag = flag.Duration("timeout", 15*time.Minute, "Timeout for the program before it must clean up")
)

const (
	// xDisplay is the X server address.
	xDisplay = ":0"
)

// logMu protects log output.
var logMu sync.Mutex

// log logs a message to stderr. `format` should not have a newline.
// This does not use the standard logging library because this program needs
// to support logging multiple lines atomically.
func log(format string, values ...any) {
	logDo(func() {
		fmt.Fprintf(os.Stderr, "%s\n", fmt.Sprintf(format, values...))
	})
}

// logDo runs a function while logging the log lock.
// This is useful to log multiple lines at a time.
func logDo(fn func()) {
	logMu.Lock()
	defer logMu.Unlock()
	fn()
}

// logWriter implements io.Writer and logs to stderr.
type logWriter struct{}

func (w *logWriter) Write(p []byte) (n int, err error) {
	logDo(func() {
		n, err = os.Stderr.Write(p)
	})
	return n, err
}

// Command wraps a command with some niceties for stdout/stderr handling.
type Command struct {
	// Cmd is the wrapped command.
	Cmd *exec.Cmd

	// Option fields.
	// If non-nil, this data will be fed to the command's stdin.
	Stdin []byte
	// ForwardStdout and ForwardStderr control whether stdout/stderr are
	// forwarded to the user's console.
	ForwardStdout, ForwardStderr bool
	// PrefixStdout and PrefixStderr are prefixes for forwarded logs.
	PrefixStdout, PrefixStderr string

	// streamWG waits for stdout/stderr capturing goroutines.
	streamWG sync.WaitGroup

	// mu protects the fields below.
	mu sync.Mutex

	// started is `true` if the command has started.
	started bool

	// Sets of stdout/stderr/combined output lines.
	stdoutLines, stderrLines, combined []string

	// waitErr is the error returned by `Cmd.Wait`.
	waitErr error

	// doneCh is closed when the command is done running.
	doneCh chan struct{}
}

// Start starts a command in the background.
func (c *Command) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started {
		return errors.New("command already started")
	}
	for _, env := range os.Environ() {
		c.Cmd.Env = append(c.Cmd.Env, env)
	}
	if len(c.Stdin) == 0 {
		c.Cmd.Stdin = nil // Read from /dev/null
	} else {
		c.Cmd.Stdin = bytes.NewReader(c.Stdin)
	}
	stdout, err := c.Cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("cannot open stdout pipe: %w", err)
	}
	stderr, err := c.Cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("cannot open stderr pipe: %w", err)
	}
	if err := c.Cmd.Start(); err != nil {
		return fmt.Errorf("cannot start command: %w", err)
	}
	c.started = true

	for _, stream := range []struct {
		forward bool
		prefix  string
		from    io.ReadCloser
		to      io.Writer
		lines   *[]string
	}{
		{c.ForwardStdout, c.PrefixStdout, stdout, os.Stdout, &c.stdoutLines},
		{c.ForwardStderr, c.PrefixStderr, stderr, &logWriter{}, &c.stderrLines},
	} {
		c.streamWG.Add(1)
		go func(forward bool, prefix string, from io.ReadCloser, to io.Writer, lines *[]string) {
			defer c.streamWG.Done()
			for scanner := bufio.NewScanner(from); scanner.Scan(); {
				text := scanner.Text()
				c.mu.Lock()
				*lines = append(*lines, text)
				c.combined = append(c.combined, text)
				if forward {
					fmt.Fprintf(to, "%s%s\n", prefix, text)
				}
				c.mu.Unlock()
			}
		}(stream.forward, stream.prefix, stream.from, stream.to, stream.lines)
	}
	c.doneCh = make(chan struct{})
	go func() {
		c.streamWG.Wait()
		c.mu.Lock()
		defer c.mu.Unlock()
		c.waitErr = c.Cmd.Wait()
		close(c.doneCh)
	}()
	return nil
}

// Stdout returns the standard output lines of the command so far.
func (c *Command) Stdout() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stdoutLines[:]
}

// Stderr returns the standard error lines of the command so far.
func (c *Command) Stderr() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stderrLines[:]
}

// Combined returns the combined stodut/stderr lines of the command so far.
// This is not the same as stdout concatenated with stderr, as it preserves
// line ordering as they were emitted.
func (c *Command) Combined() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.combined[:]
}

// PID returns the PID of the running command.
func (c *Command) PID() int {
	return c.Cmd.Process.Pid
}

// ExitCode returns the exit code of the command.
func (c *Command) ExitCode(ctx context.Context) (int, error) {
	c.mu.Lock()
	if !c.started {
		c.mu.Unlock()
		return 0, errors.New("command not started")
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-c.Done():
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.waitErr == nil {
		return 0, nil
	}
	if exitErr := (*exec.ExitError)(nil); errors.As(c.waitErr, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	return 0, fmt.Errorf("process exit did not carry exit code: %w", c.waitErr)
}

// Wait waits for a `Start`ed command to run to completion and returns
// stdout/stderr.
func (c *Command) Wait(ctx context.Context) ([]string, []string, error) {
	c.mu.Lock()
	if !c.started {
		c.mu.Unlock()
		return nil, nil, errors.New("command not started")
	}
	c.mu.Unlock()
	select {
	case <-ctx.Done():
	case <-c.Done():
	}
	stdout := c.Stdout()
	stderr := c.Stderr()
	c.mu.Lock()
	err := c.waitErr
	c.mu.Unlock()
	if err != nil {
		return stdout, stderr, fmt.Errorf("command failed: %w", err)
	}
	return stdout, stderr, err
}

// Run `Start`s and `Wait`s for a command to run to completion.
func (c *Command) Run(ctx context.Context) ([]string, []string, error) {
	if err := c.Start(ctx); err != nil {
		return nil, nil, err
	}
	return c.Wait(ctx)
}

// CombinedOutput runs a command to completion and returns combined
// stdout/stderr output.
func (c *Command) CombinedOutput(ctx context.Context) (string, error) {
	if err := c.Start(ctx); err != nil {
		return "", err
	}
	_, _, err := c.Wait(ctx)
	return strings.Join(c.Combined(), "\n"), err
}

// Done returns a channel that is closed when the command terminates.
// Must be called after `Start`.
func (c *Command) Done() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.doneCh == nil {
		panic("Command.Done called before Command.Start")
	}
	return c.doneCh
}

// Terminate terminates a process.
// It does not reap the process; the caller should call wait if appropriate.
func Terminate(ctx context.Context, pid int, waitChans ...<-chan struct{}) error {
	unifiedWaitChan := make(chan struct{})
	waitShutdown := make(chan struct{})
	defer close(waitShutdown)
	for _, waitChan := range waitChans {
		go func(waitChan <-chan struct{}) {
			select {
			case <-waitShutdown:
			case <-waitChan:
				unifiedWaitChan <- struct{}{}
			}
		}(waitChan)
	}
	// Ignore errors here because it doesn't matter; we will re-detect
	// the post-signal process state later.
	_ = syscall.Kill(pid, syscall.SIGTERM)
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
	case <-unifiedWaitChan:
	}
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err != nil && os.IsNotExist(err) {
		// The process is gone, so we are successful.
		return nil
	}
	// Otherwise, send SIGKILL.
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		return fmt.Errorf("cannot send SIGKILL: %w", err)
	}
	return nil
}

// XServer represents an X server.
type XServer struct {
	xvfb *Command
}

// NewXServer creates a new X server.
func NewXServer(ctx context.Context) (*XServer, error) {
	xvfb := &Command{
		Cmd:           exec.CommandContext(ctx, "Xvfb", xDisplay, "-screen", "0", "1920x1080x24"),
		ForwardStdout: true,
		PrefixStdout:  "[Xvfb:stdout] ",
		ForwardStderr: true,
		PrefixStderr:  "[Xvfb:stderr] ",
	}
	if err := xvfb.Start(ctx); err != nil {
		return nil, fmt.Errorf("cannot start X server: %w", err)
	}
	x := &XServer{xvfb: xvfb}
	if err := x.Probe(ctx); err != nil {
		x.Shutdown(ctx)
		return nil, fmt.Errorf("X server did not start in time: %w", err)
	}
	return x, nil
}

// Env returns the DISPLAY environment variable to use for this X server.
func (x *XServer) Env() string {
	return fmt.Sprintf("DISPLAY=%s", xDisplay)
}

// Command returns a command that runs in the context of this X server.
func (x *XServer) Command(ctx context.Context, argv ...string) *Command {
	cmd := &Command{Cmd: exec.CommandContext(ctx, argv[0], argv[1:]...)}
	cmd.Cmd.Env = append(cmd.Cmd.Env, x.Env())
	return cmd
}

// Probe probes the X server to see if it is alive.
func (x *XServer) Probe(ctx context.Context) error {
	probeCtx, probeCancel := context.WithTimeout(ctx, 10*time.Second)
	defer probeCancel()
	lastErr := ctx.Err()
	for probeCtx.Err() == nil {
		output, err := x.Command(probeCtx, "xset", "q").CombinedOutput(ctx)
		if err == nil {
			return nil
		}
		lastErr = fmt.Errorf("cannot probe X server: %w: %s", err, output)
	}
	return lastErr
}

// Shutdown attempts to shut down the X server.
func (x *XServer) Shutdown(ctx context.Context) error {
	if err := Terminate(ctx, x.xvfb.Cmd.Process.Pid, x.xvfb.Done()); err != nil {
		return fmt.Errorf("cannot shut down Xvfb: %w", err)
	}
	_, _, _ = x.xvfb.Wait(ctx) // Reap, ignore errors.
	return nil
}

// XWindow represents a window in the X server.
type XWindow struct {
	x  *XServer
	id int64
}

// Windows returns a list of X windows.
func (x *XServer) Windows(ctx context.Context) ([]*XWindow, error) {
	cmd := x.Command(ctx, "xdotool", "search", "--all", ".*")
	stdout, _, err := cmd.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("xdotool search failed: %w (output: %v)", err, cmd.Combined())
	}
	windows := make([]*XWindow, 0, len(stdout))
	for _, line := range stdout {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		windowID, err := strconv.Atoi(line)
		if err != nil {
			return nil, fmt.Errorf("unexpected xdotool output: %q (whole output: %v)", line, cmd.Combined())
		}
		windows = append(windows, &XWindow{x: x, id: int64(windowID)})
	}
	return windows, nil
}

// ID returns a the window ID as a string.
func (w *XWindow) ID() string {
	return fmt.Sprintf("%d", w.id)
}

// String returns a string containing the window ID.
func (w *XWindow) String() string {
	return fmt.Sprintf("window:%d", w.id)
}

// Title returns the window title.
func (w *XWindow) Title(ctx context.Context) (string, error) {
	cmd := w.x.Command(ctx, "xdotool", "getwindowname", w.ID())
	stdout, stderr, err := cmd.Wait(ctx)
	if err != nil {
		return "", w.diagnoseErr(ctx, fmt.Errorf("cannot get window %s title: %w (%q)", w, err, strings.Join(stderr, "\n")))
	}
	if len(stdout) != 1 || stdout[0] == "" {
		return "", w.diagnoseErr(ctx, fmt.Errorf("cannot get window %s title: unexpected output %q", w, strings.Join(stdout, "\n")))
	}
	return stdout[0], nil
}

// PID returns the PID controlling the window.
// Note that this information is only optionally specified by a process
// creating a window, and is never guaranteed to be there.
func (w *XWindow) PID(ctx context.Context) (int, error) {
	cmd := w.x.Command(ctx, "xdotool", "getwindowpid", w.ID())
	stdout, stderr, err := cmd.Wait(ctx)
	if err != nil {
		return -1, w.diagnoseErr(ctx, fmt.Errorf("cannot get window %s PID: %w (%q)", w, err, strings.Join(stderr, "\n")))
	}
	if len(stdout) != 1 || stdout[0] == "" {
		return -1, w.diagnoseErr(ctx, fmt.Errorf("cannot get window %s PID: unexpected output %q", w, strings.Join(stdout, "\n")))
	}
	pid, err := strconv.Atoi(stdout[0])
	if err != nil {
		return -1, w.diagnoseErr(ctx, fmt.Errorf("cannot get window %s PID: invalid PID %q: %w", w, stdout[0], err))
	}
	return pid, nil
}

// Activate activates or focuses the X window.
func (w *XWindow) Activate(ctx context.Context) error {
	cmd := w.x.Command(ctx, "xdotool", "windowactivate", "--sync", w.ID())
	if output, err := cmd.CombinedOutput(ctx); err != nil {
		return w.diagnoseErr(ctx, fmt.Errorf("xdotool windowactivate: %w (output: %q)", err, output))
	}
	return nil
}

// Keystroke sends a keystroke to the X window.
func (w *XWindow) Keystroke(ctx context.Context, keystrokes ...string) error {
	cmd := w.x.Command(
		ctx,
		append(
			[]string{
				"xdotool",
				"key",
				"--clearmodifiers",
				"--window",
				w.ID(),
			},
			keystrokes...)...)
	if output, err := cmd.CombinedOutput(ctx); err != nil {
		return w.diagnoseErr(ctx, fmt.Errorf("xdotool key: %w (output: %q)", err, output))
	}
	return nil
}

// Screenshot takes a screenshot image of the X window.
func (w *XWindow) Screenshot(ctx context.Context) (image.Image, error) {
	screenshotCtx, screenshotCancel := context.WithTimeout(ctx, 10*time.Second)
	// Need to use a raw `exec.Command` here because stdout is a byte stream
	// as opposed to a text stream.
	cmd := exec.CommandContext(screenshotCtx, "import", "-window", w.ID(), "png:-" /* Save to stdout as PNG */)
	cmd.Env = append(cmd.Env, w.x.Env())
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	err := cmd.Run()
	screenshotCancel()
	stderr := string(stderrBuf.Bytes())
	if err != nil {
		// Best-effort attempt to kill the process.
		_ = Terminate(ctx, cmd.Process.Pid)
		return nil, w.diagnoseErr(ctx, fmt.Errorf("imagemagick failed: %w (output: %q)", err, stderr))
	}
	img, err := png.Decode(&stdoutBuf)
	if err != nil {
		return nil, w.diagnoseErr(ctx, fmt.Errorf("cannot decode screenshot image: %w (output: %q)", err, stderr))
	}
	if size := img.Bounds().Size(); size.X == 0 || size.Y == 0 {
		return nil, w.diagnoseErr(ctx, fmt.Errorf("screenshot image has zero dimension (output: %q)", stderr))
	}
	return img, nil
}

// diagnoseErr annotates an error with additional window information.
func (w *XWindow) diagnoseErr(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	probeCtx, probeCancel := context.WithTimeout(ctx, 1*time.Second)
	defer probeCancel()
	if xErr := w.x.Probe(probeCtx); xErr != nil {
		return fmt.Errorf("%w (X server is down: %v)", err, xErr)
	}
	winInfo, infoErr := w.x.Command(ctx, "xwininfo", "-id", w.ID()).CombinedOutput(ctx)
	if infoErr != nil {
		return fmt.Errorf("%w (cannot get window info: %v - %q)", err, infoErr, winInfo)
	}
	return fmt.Errorf("%w (window info: %q)", err, winInfo)
}

// SampleTest represents a single sample test to execute.
type SampleTest struct {
	TestName string
	XServer  *XServer
	testBin  string
}

// NewSampleTest creates a new SampleTest.
func NewSampleTest(testName string, x *XServer) (*SampleTest, error) {
	st := &SampleTest{TestName: testName, XServer: x}
	if _, err := os.Stat(st.dir()); err != nil {
		return nil, fmt.Errorf("invalid test %q: directory %q: %w", st.TestName, st.dir(), err)
	}

	testBin, err := st.bin()
	if err != nil {
		return nil, fmt.Errorf("failed to find testBin path on test %q: %v", st.TestName, err)
	}
	st.testBin = testBin

	return st, nil
}

// dir returns the test directory.
func (st *SampleTest) dir() string {
	const samplesRoot = "/cuda-samples/build/Samples"
	return path.Join(samplesRoot, st.TestName)
}

func (st *SampleTest) bin() (string, error) {
	parts := strings.SplitN(st.TestName, "/", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("failed to split test into parts: %q", st.TestName)
	}
	return fmt.Sprintf("%s/%s", st.dir(), parts[1]), nil
}

// cmd returns a `*Command` with proper environment variables and
// working directory for the test. Its output is forwarded to the console.
func (st *SampleTest) cmd(ctx context.Context, argv ...string) *Command {
	argv0Base := path.Base(argv[0])
	cmd := st.XServer.Command(ctx, argv...)
	cmd.Cmd.Dir = st.dir()
	cmd.ForwardStdout = true
	cmd.PrefixStdout = fmt.Sprintf("[%s:%s:stdout] ", st.TestName, argv0Base)
	cmd.ForwardStderr = true
	cmd.PrefixStderr = fmt.Sprintf("[%s:%s:stderr] ", st.TestName, argv0Base)
	return cmd
}

// quietCmd returns a `*Command` with proper environment variables and
// working directory for the test. Its output is not forwarded to the console.
func (st *SampleTest) quietCmd(ctx context.Context, argv ...string) *Command {
	cmd := st.cmd(ctx, argv...)
	cmd.ForwardStdout = false
	cmd.ForwardStderr = false
	return cmd
}

// SampleState captures states that is captured before a test runs, and that
// is useful to refer to while (or after) the test is running.
type SampleState struct {
	// When is the timestamp at which this SampleState was taken.
	When time.Time

	// Executables holds clean paths of all executable files in the test dir.
	Executables map[string]struct{}

	// Windows is a list of window screenshots in the X server, mapped by ID.
	Windows map[string]*XWindow

	// Screenshots is a list of screenshots mapped by window ID.
	// If a screenshot fails, the window is mapped to `nil`.
	Screenshots map[string]image.Image
}

// NewExecutables returns the executables in `after` that are not in `ss`.
func (ss *SampleState) NewExecutables(after *SampleState) []string {
	newExecutables := make([]string, 0, len(after.Executables))
	for e := range after.Executables {
		if _, found := ss.Executables[e]; !found {
			newExecutables = append(newExecutables, e)
		}
	}
	return newExecutables
}

// DifferentWindows returns the windows in `after` that are new or for which
// the screenshot has changed.
func (ss *SampleState) DifferentWindows(after *SampleState) []*XWindow {
	diffWindows := make([]*XWindow, 0, len(after.Windows))
	for id, window := range after.Windows {
		if _, found := ss.Windows[id]; !found {
			diffWindows = append(diffWindows, window)
			continue
		}
		if !imgEq(ss.Screenshots[id], after.Screenshots[id]) {
			diffWindows = append(diffWindows, window)
		}
	}
	return diffWindows
}

// imgEq returns true if the two given images are identical in size and pixel
// values.
func imgEq(a, b image.Image) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	bounds := a.Bounds()
	if bounds != b.Bounds() {
		return false
	}
	// Convert images to RGBA so that we can compare raw pixel data directly.
	imgA := image.NewRGBA(bounds)
	draw.Draw(imgA, bounds, a, image.Point{0, 0}, draw.Src)
	imgB := image.NewRGBA(bounds)
	draw.Draw(imgB, bounds, b, image.Point{0, 0}, draw.Src)
	if imgA.Stride != imgB.Stride || imgA.Rect != imgB.Rect || len(imgA.Pix) != len(imgB.Pix) {
		return false
	}
	for i := 0; i < len(imgA.Pix); i++ {
		if imgA.Pix[i] != imgB.Pix[i] {
			return false
		}
	}
	return true
}

// logImageWithPrefix renders an image to text, frames it with the given
// title, and logs that with a given prefix.
func logImageWithFrameAndPrefix(ctx context.Context, img image.Image, title, prefix string) error {
	const imageWidth = 72
	var pngBytes bytes.Buffer
	if err := png.Encode(&pngBytes, img); err != nil {
		return fmt.Errorf("png encoding failed: %v", err)
	}
	stdout, stderr, err := (&Command{
		Cmd:   exec.CommandContext(ctx, "ascii-image-converter", "/dev/stdin", fmt.Sprintf("--width=%d", imageWidth), "--braille", "--dither"),
		Stdin: pngBytes.Bytes(),
	}).Run(ctx)
	if err != nil {
		return fmt.Errorf("ascii-image-converter failed: %v (output: %q)", err, strings.Join(stderr, "\n"))
	}
	header := "┍"
	footer := "╰"
	numHeaderHorizontalLines := imageWidth - len(title) - 2
	leftHeaderHorizontalLines := numHeaderHorizontalLines / 2
	rightHeaderHorizontalLines := numHeaderHorizontalLines - leftHeaderHorizontalLines
	for i := 0; i < leftHeaderHorizontalLines; i++ {
		header += "━"
	}
	header += fmt.Sprintf(" %s ", title)
	for i := 0; i < rightHeaderHorizontalLines; i++ {
		header += "━"
	}
	for i := 0; i < imageWidth; i++ {
		footer += "─"
	}
	header += "┑"
	footer += "╯"
	logDo(func() {
		fmt.Fprintf(os.Stderr, "%s%s\n", prefix, header)
		for _, line := range stdout {
			fmt.Fprintf(os.Stderr, "%s|%s|\n", prefix, line)
		}
		fmt.Fprintf(os.Stderr, "%s%s\n", prefix, footer)
	})
	return nil
}

// State returns the current state of the test.
func (st *SampleTest) State(ctx context.Context) (*SampleState, error) {
	when := time.Now()
	executables := make(map[string]struct{})
	err := filepath.Walk(st.dir(), func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("cannot walk %q (%q): %w", st.dir(), path, err)
		}
		if !info.IsDir() && info.Mode()&0111 != 0 {
			executables[path] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("cannot list executables: %w", err)
	}
	windows, err := st.XServer.Windows(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot list windows: %w", err)
	}
	windowMap := make(map[string]*XWindow, len(windows))
	screenshots := make(map[string]image.Image, len(windows))
	for _, w := range windows {
		windowMap[w.ID()] = w
		if screenshot, err := w.Screenshot(ctx); err == nil {
			screenshots[w.ID()] = screenshot
		}
	}
	return &SampleState{
		When:        when,
		Executables: executables,
		Windows:     windowMap,
		Screenshots: screenshots,
	}, nil
}

// Run runs `make run` or `make testrun` in the test directory.
func (st *SampleTest) makeRun(ctx context.Context) (*Command, error) {
	arch, err := st.quietCmd(ctx, "uname", "-m").CombinedOutput(ctx)
	if err != nil || arch == "" {
		return nil, fmt.Errorf("cannot get architecture (%q): %w", arch, err)
	}

	argv := []string{"make", "-C", st.dir(), fmt.Sprintf("TARGET_ARCH=%s", arch)}
	log("[%s] Executing: %v", st.TestName, strings.Join(argv, " "))
	cmd := st.cmd(ctx, argv...)
	if err := cmd.Start(ctx); err != nil {
		return nil, fmt.Errorf("cannot start `make`: %w", err)
	}
	return cmd, nil
}

// Run runs a single sample test.
func (st *SampleTest) Run(ctx context.Context) error {
	if _, _, err := st.cmd(ctx, "make", "-C", st.dir(), "clean").Run(ctx); err != nil {
		return fmt.Errorf("cannot run `make clean`: %w", err)
	}
	stateBefore, err := st.State(ctx)
	if err != nil {
		return fmt.Errorf("cannot get state before test: %w", err)
	}
	makeRun, err := st.makeRun(ctx)
	if err != nil {
		return fmt.Errorf("cannot run `make run`: %w", err)
	}
	defer Terminate(ctx, makeRun.PID())
	// There are multiple possibilities here.
	// Some CUDA programs will run an X application that runs forever.
	// In this case, we need to detect this and to make sure it runs,
	// then kill it.
	// Other programs are just command-line based and run to completion,
	// and we rely on their exit code.
	// To determine this, we first just wait for a few seconds and see what
	// the command does.
	if err := st.Monitor(ctx, makeRun, stateBefore); err != nil {
		return fmt.Errorf("test failed in `make run`: %w", err)
	}

	_, err = os.Stat(st.testBin)
	if err != nil {
		return fmt.Errorf("failed to stat file executable %q: %v", st.testBin, err)
	}

	if _, _, err := st.cmd(ctx, st.testBin).Run(ctx); err != nil {
		fmt.Errorf("failed to run bin %q: %v", st.testBin, err)
	}
	return nil
}

// Monitor monitors whether a `make run` command terminates quickly or
// produces an X window.
func (st *SampleTest) Monitor(ctx context.Context, makeRun *Command, stateBefore *SampleState) error {
	fastTicker := time.NewTicker(200 * time.Millisecond)
	defer fastTicker.Stop()
	var currentState *SampleState
	for windowsChanged := false; !windowsChanged; {
		select {
		case <-ctx.Done(): // Context expired.
			return ctx.Err()
		case <-makeRun.Done(): // `make run` finished on its own.
			_, _, err := makeRun.Wait(ctx)
			return err
		case <-fastTicker.C:
			// Check for new windows.
			var err error
			currentState, err = st.State(ctx)
			if err != nil {
				return fmt.Errorf("cannot get test state: %w", err)
			}
			windowsChanged = len(stateBefore.DifferentWindows(currentState)) > 0
		}
	}

	// If we get here, the test produces X windows. So we need to monitor them.
	// We will consider the test a success in any of the following cases:
	//  - The `make run` process exits at any time with a 0 exit code.
	//  - The set of windows stops changing for 3 consecutive seconds, i.e.
	//    the test has reached a stable steady state without crashing.
	//  - The set of windows continuously changes for 10 consecutive seconds,
	//    i.e. the test is likely a visually-changing demo over time and has
	//    reached a steady state without crashing.
	log("[%s] This appears to be a test that uses graphics and X windows.", st.TestName)
	lastState := stateBefore
	slowTicker := time.NewTicker(1 * time.Second)
	defer slowTicker.Stop()
	lastWindowChange := currentState.When
	successDeadline := time.After(10 * time.Second)
	for {
		select {
		case <-ctx.Done(): // Context expired.
			return ctx.Err()
		case <-makeRun.Done(): // `make run` finished on its own.
			_, _, err := makeRun.Wait(ctx)
			return err
		case <-successDeadline: // Still no crashes after long enough.
			return st.TerminateWindowTest(ctx, makeRun, stateBefore)
		case <-slowTicker.C:
			stateNow, err := st.State(ctx)
			if err != nil {
				return fmt.Errorf("cannot get test state: %w", err)
			}
			if differentWindows := lastState.DifferentWindows(stateNow); len(differentWindows) > 0 {
				lastWindowChange = stateNow.When
				log("[%s] [%s] Windows changed:", st.TestName, stateNow.When.Format("15:04:05"))
				for _, window := range differentWindows {
					title, err := window.Title(ctx)
					if err != nil {
						title = window.String()
					}
					if screenshot := stateNow.Screenshots[window.ID()]; screenshot == nil {
						log("[%s:%s] <screenshot failed>", st.TestName, title)
					} else if err := logImageWithFrameAndPrefix(ctx, screenshot, title, fmt.Sprintf("[%s] ", st.TestName)); err != nil {
						log("[%s:%s] <rendering screenshot failed: %v>", st.TestName, title, err)
					}
				}
			}
			if currentState.When.Sub(lastWindowChange) >= 3*time.Second {
				return st.TerminateWindowTest(ctx, makeRun, stateBefore)
			}
			lastState = stateNow
		}
	}
}

// TerminateWindowTest terminates a sample test that produces X windows.
func (st *SampleTest) TerminateWindowTest(ctx context.Context, makeRun *Command, stateBefore *SampleState) error {
	stateNow, err := st.State(ctx)
	if err != nil {
		return fmt.Errorf("cannot get test state: %w", err)
	}
	testWindows := stateBefore.DifferentWindows(stateNow)
	// Most windows-based tests accept typing the letter "Q" to quit them.
	// Try it first.
	for _, window := range testWindows {
		// Ignore error for both activation and keystrokes; this is just a
		// best-effort attempt to press "Q".
		_ = window.Activate(ctx)
		_ = window.Keystroke(ctx, "q")
	}
	// Now wait a little bit to see if the program ends on its own from that.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-makeRun.Done():
		_, _, err = makeRun.Wait(ctx)
		return err
	case <-time.After(3 * time.Second):
		// Didn't work, keep going.
	}
	// Gather a list of test PIDs.
	windowPIDs := make(map[int]struct{})
	for _, window := range testWindows {
		pid, err := window.PID(ctx)
		if err != nil {
			// X window PID information is optional; erroring out here is not
			// appropriate.
			continue
		}
		if pid == makeRun.PID() {
			continue
		}
		windowPIDs[pid] = struct{}{}
	}
	if len(windowPIDs) > 0 {
		// Kill all the PIDs we gathered.
		for pid := range windowPIDs {
			_ = Terminate(ctx, pid, makeRun.Done())
		}
		// Now check if `make run` terminates on its own.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-makeRun.Done():
			_, _, err = makeRun.Wait(ctx)
			return err
		case <-time.After(3 * time.Second):
			// Didn't work, keep going.
		}
	}
	return errors.New("test did not terminate")
}

// Main is the main method of this program.
func Main(ctx context.Context) (int, error) {
	flag.Parse()
	if nvCaps := os.Getenv("NVIDIA_DRIVER_CAPABILITIES"); nvCaps != "all" {
		return 1, fmt.Errorf("NVIDIA_DRIVER_CAPABILITIES is not set to 'all' (got %q); please set it to 'all' and try again", nvCaps)
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(ctx, *timeoutFlag)
	defer cleanupCancel()
	deadline, _ := cleanupCtx.Deadline()
	x, err := NewXServer(cleanupCtx)
	if err != nil {
		return 1, fmt.Errorf("failed to start X server: %s", err)
	}
	defer x.Shutdown(cleanupCtx)
	testsCtx, testsCancel := context.WithDeadline(cleanupCtx, deadline.Add(-10*time.Second))
	defer testsCancel()
	numTests := 0
	exitCode := 1
	var lastErr error

	for _, testName := range flag.Args() {
		numTests++
		st, err := NewSampleTest(testName, x)
		if err != nil {
			log("> Invalid test %q: %s", testName, err)
			lastErr = fmt.Errorf("invalid test %q: %w", testName, err)
			continue
		}
		log("> Running test: %s", testName)
		testCtx, testCancel := context.WithCancel(testsCtx)
		err = st.Run(testCtx)
		testCancel()
		if err != nil {
			log("> Test failed: %s (%s)", testName, err)
			lastErr = fmt.Errorf("test %q failed: %w", testName, err)
			if exitErr := (*exec.ExitError)(nil); errors.As(err, &exitErr) && exitErr.ExitCode() > 0 {
				exitCode = exitErr.ExitCode()
			}
			continue
		}
		log("> Test passed: %s", testName)
	}
	if numTests == 0 {
		return 1, fmt.Errorf("no tests to run, failing vacuously; specify test names as positional arguments")
	}
	if lastErr == nil {
		return 0, nil
	}
	if numTests != 1 {
		return 1, fmt.Errorf("one or more tests failed (last error: %w)", lastErr)
	}
	// If there was a single test to run, pass along its error code if it
	// had one. (It may not have had one in case the test failed for another
	// reason, e.g. error setting up the test prior to running it.)
	if exitCode == 0 {
		exitCode = 1
	}
	return exitCode, fmt.Errorf("test failed: %w", lastErr)
}

func main() {
	exitCode, err := Main(context.Background())
	if err != nil {
		log("%s", err)
		log("FAIL")
	} else {
		log("PASS")
	}
	os.Exit(exitCode)
}
