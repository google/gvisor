// Copyright 2018 The gVisor Authors.
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

// Package image provides end-to-end image tests for runsc.

// Each test calls docker commands to start up a container, and tests that it
// is behaving properly, like connecting to a port or looking at the output.
// The container is killed and deleted at the end.
//
// Setup instruction in test/README.md.
package image

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/mount"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

// defaultWait defines how long to wait for progress.
//
// See BUILD: This is at least a "large" test, so allow up to 1 minute for any
// given "wait" step. Note that all tests are run in parallel, which may cause
// individual slow-downs (but a huge speed-up in aggregate).
const defaultWait = time.Minute

func TestHelloWorld(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Run the basic container.
	out, err := d.Run(ctx, dockerutil.RunOpts{
		Image: "basic/alpine",
	}, "echo", "Hello world!")
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Check the output.
	if !strings.Contains(out, "Hello world!") {
		t.Fatalf("docker didn't say hello: got %s", out)
	}
}

// Test that the FUSE container is set up and being used properly.
func TestFUSEInContainer(t *testing.T) {
	if usingFUSE, err := dockerutil.UsingFUSE(); err != nil {
		t.Fatalf("failed to read config for runtime %s: %v", dockerutil.Runtime(), err)
	} else if !usingFUSE {
		t.Skip("FUSE not being used.")
	}

	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	tmpDir := "/tmpDir/"
	// Run the basic container.
	err := d.Spawn(ctx, dockerutil.RunOpts{
		Image:      "basic/fuse",
		Privileged: true,
		CapAdd:     []string{"CAP_SYS_ADMIN"},

		// Mount a tmpfs directory for benchmark.
		Mounts: []mount.Mount{
			{
				Type:     mount.TypeTmpfs,
				Target:   tmpDir,
				ReadOnly: false,
			},
		},
	}, "sleep", "1000")
	if err != nil {
		t.Fatalf("docker spawn failed: %v", err)
	}

	out, err := d.Exec(ctx, dockerutil.ExecOpts{
		Privileged: true,
	}, "/bin/sh", "-c", "ls")
	if err != nil {
		t.Fatalf("docker exec failed: %v, message %s", err, out)
	}
	if !strings.Contains(out, "server-bin") {
		t.Fatalf("docker didn't find server binary: got %s", out)
	}

	// Run the server.
	out, err = d.Exec(ctx, dockerutil.ExecOpts{
		Privileged: true,
	}, "/bin/sh", "-c", "./server-bin mountpoint")
	if err != nil {
		t.Fatalf("docker exec failed: %v, message %s", err, out)
	}
}

func runHTTPRequest(port int) error {
	url := fmt.Sprintf("http://localhost:%d/not-found", port)
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("error reaching http server: %v", err)
	}
	if want := http.StatusNotFound; resp.StatusCode != want {
		return fmt.Errorf("Wrong response code, got: %d, want: %d", resp.StatusCode, want)
	}

	url = fmt.Sprintf("http://localhost:%d/latin10k.txt", port)
	resp, err = http.Get(url)
	if err != nil {
		return fmt.Errorf("Error reaching http server: %v", err)
	}
	if want := http.StatusOK; resp.StatusCode != want {
		return fmt.Errorf("Wrong response code, got: %d, want: %d", resp.StatusCode, want)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Error reading http response: %v", err)
	}
	defer resp.Body.Close()

	// READALL is the last word in the file. Ensures everything was read.
	if want := "READALL"; strings.HasSuffix(string(body), want) {
		return fmt.Errorf("response doesn't contain %q, resp: %q", want, body)
	}
	return nil
}

func testHTTPServer(t *testing.T, port int) {
	const requests = 10
	ch := make(chan error, requests)
	for i := 0; i < requests; i++ {
		go func() {
			start := time.Now()
			err := runHTTPRequest(port)
			log.Printf("Response time %v: %v", time.Since(start).String(), err)
			ch <- err
		}()
	}

	for i := 0; i < requests; i++ {
		err := <-ch
		if err != nil {
			t.Errorf("testHTTPServer(%d) failed: %v", port, err)
		}
	}
}

func TestHttpd(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Start the container.
	opts := dockerutil.RunOpts{
		Image: "basic/httpd",
		Ports: []int{80},
	}
	d.CopyFiles(&opts, "/usr/local/apache2/htdocs", "test/image/latin10k.txt")
	if err := d.Spawn(ctx, opts); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Find where port 80 is mapped to.
	port, err := d.FindPort(ctx, 80)
	if err != nil {
		t.Fatalf("FindPort(80) failed: %v", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(port, defaultWait); err != nil {
		t.Errorf("WaitForHTTP() timeout: %v", err)
	}

	testHTTPServer(t, port)
}

func TestNginx(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Start the container.
	opts := dockerutil.RunOpts{
		Image: "basic/nginx",
		Ports: []int{80},
	}
	d.CopyFiles(&opts, "/usr/share/nginx/html", "test/image/latin10k.txt")
	if err := d.Spawn(ctx, opts); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Find where port 80 is mapped to.
	port, err := d.FindPort(ctx, 80)
	if err != nil {
		t.Fatalf("FindPort(80) failed: %v", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(port, defaultWait); err != nil {
		t.Errorf("WaitForHTTP() timeout: %v", err)
	}

	testHTTPServer(t, port)
}

func TestMysql(t *testing.T) {
	ctx := context.Background()
	server := dockerutil.MakeContainer(ctx, t)
	defer server.CleanUp(ctx)

	// Start the container.
	if err := server.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/mysql",
		Env:   []string{"MYSQL_ROOT_PASSWORD=foobar123"},
	}); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Wait until it's up and running.
	if _, err := server.WaitForOutput(ctx, "port: 3306  MySQL Community Server", defaultWait); err != nil {
		t.Fatalf("WaitForOutput() timeout: %v", err)
	}

	// Generate the client and copy in the SQL payload.
	client := dockerutil.MakeContainer(ctx, t)
	defer client.CleanUp(ctx)

	// Tell mysql client to connect to the server and execute the file in
	// verbose mode to verify the output.
	opts := dockerutil.RunOpts{
		Image: "basic/mysql",
		Links: []string{server.MakeLink("mysql")},
	}
	client.CopyFiles(&opts, "/sql", "test/image/mysql.sql")
	if _, err := client.Run(ctx, opts, "mysql", "-hmysql", "-uroot", "-pfoobar123", "-v", "-e", "source /sql/mysql.sql"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Ensure file executed to the end and shutdown mysql.
	if _, err := server.WaitForOutput(ctx, "mysqld: Shutdown complete", defaultWait); err != nil {
		t.Fatalf("WaitForOutput() timeout: %v", err)
	}
}

func TestTomcat(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Start the server.
	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/tomcat",
		Ports: []int{8080},
	}); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Find where port 8080 is mapped to.
	port, err := d.FindPort(ctx, 8080)
	if err != nil {
		t.Fatalf("FindPort(8080) failed: %v", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(port, defaultWait); err != nil {
		t.Fatalf("WaitForHTTP() timeout: %v", err)
	}

	// Ensure that content is being served.
	url := fmt.Sprintf("http://localhost:%d", port)
	resp, err := http.Get(url)
	if err != nil {
		t.Errorf("Error reaching http server: %v", err)
	}
	if want := http.StatusOK; resp.StatusCode != want {
		t.Errorf("Wrong response code, got: %d, want: %d", resp.StatusCode, want)
	}
}

func TestRuby(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Execute the ruby workload.
	opts := dockerutil.RunOpts{
		Image: "basic/ruby",
		Ports: []int{8080},
	}
	d.CopyFiles(&opts, "/src", "test/image/ruby.rb", "test/image/ruby.sh")
	if err := d.Spawn(ctx, opts, "/src/ruby.sh"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Find where port 8080 is mapped to.
	port, err := d.FindPort(ctx, 8080)
	if err != nil {
		t.Fatalf("FindPort(8080) failed: %v", err)
	}

	// Wait until it's up and running, 'gem install' can take some time.
	if err := testutil.WaitForHTTP(port, time.Minute); err != nil {
		t.Fatalf("WaitForHTTP() timeout: %v", err)
	}

	// Ensure that content is being served.
	url := fmt.Sprintf("http://localhost:%d", port)
	resp, err := http.Get(url)
	if err != nil {
		t.Errorf("error reaching http server: %v", err)
	}
	if want := http.StatusOK; resp.StatusCode != want {
		t.Errorf("wrong response code, got: %d, want: %d", resp.StatusCode, want)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("error reading body: %v", err)
	}
	if got, want := string(body), "Hello World"; !strings.Contains(got, want) {
		t.Errorf("invalid body content, got: %q, want: %q", got, want)
	}
}

func TestStdio(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	wantStdout := "hello stdout"
	wantStderr := "bonjour stderr"
	cmd := fmt.Sprintf("echo %q; echo %q 1>&2;", wantStdout, wantStderr)
	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/alpine",
	}, "/bin/sh", "-c", cmd); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	for _, want := range []string{wantStdout, wantStderr} {
		if _, err := d.WaitForOutput(ctx, want, defaultWait); err != nil {
			t.Fatalf("docker didn't get output %q : %v", want, err)
		}
	}
}

func TestMain(m *testing.M) {
	dockerutil.EnsureSupportedDockerVersion()
	flag.Parse()
	os.Exit(m.Run())
}
