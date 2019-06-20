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

// Each test calls docker commands to start up a container, and tests that it is
// behaving properly, like connecting to a port or looking at the output. The
// container is killed and deleted at the end.
//
// Setup instruction in runsc/test/README.md.
package image

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/runsc/test/testutil"
)

func TestHelloWorld(t *testing.T) {
	d := testutil.MakeDocker("hello-test")
	if err := d.Run("hello-world"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer d.CleanUp()

	if _, err := d.WaitForOutput("Hello from Docker!", 5*time.Second); err != nil {
		t.Fatalf("docker didn't say hello: %v", err)
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
	if err := testutil.Pull("httpd"); err != nil {
		t.Fatalf("docker pull failed: %v", err)
	}
	d := testutil.MakeDocker("http-test")

	dir, err := testutil.PrepareFiles("latin10k.txt")
	if err != nil {
		t.Fatalf("PrepareFiles() failed: %v", err)
	}

	// Start the container.
	mountArg := testutil.MountArg(dir, "/usr/local/apache2/htdocs", testutil.ReadOnly)
	if err := d.Run("-p", "80", mountArg, "httpd"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer d.CleanUp()

	// Find where port 80 is mapped to.
	port, err := d.FindPort(80)
	if err != nil {
		t.Fatalf("docker.FindPort(80) failed: %v", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(port, 30*time.Second); err != nil {
		t.Errorf("WaitForHTTP() timeout: %v", err)
	}

	testHTTPServer(t, port)
}

func TestNginx(t *testing.T) {
	if err := testutil.Pull("nginx"); err != nil {
		t.Fatalf("docker pull failed: %v", err)
	}
	d := testutil.MakeDocker("net-test")

	dir, err := testutil.PrepareFiles("latin10k.txt")
	if err != nil {
		t.Fatalf("PrepareFiles() failed: %v", err)
	}

	// Start the container.
	mountArg := testutil.MountArg(dir, "/usr/share/nginx/html", testutil.ReadOnly)
	if err := d.Run("-p", "80", mountArg, "nginx"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer d.CleanUp()

	// Find where port 80 is mapped to.
	port, err := d.FindPort(80)
	if err != nil {
		t.Fatalf("docker.FindPort(80) failed: %v", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(port, 30*time.Second); err != nil {
		t.Errorf("WaitForHTTP() timeout: %v", err)
	}

	testHTTPServer(t, port)
}

func TestMysql(t *testing.T) {
	if err := testutil.Pull("mysql"); err != nil {
		t.Fatalf("docker pull failed: %v", err)
	}
	d := testutil.MakeDocker("mysql-test")

	// Start the container.
	if err := d.Run("-e", "MYSQL_ROOT_PASSWORD=foobar123", "mysql"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer d.CleanUp()

	// Wait until it's up and running.
	if _, err := d.WaitForOutput("port: 3306  MySQL Community Server", 3*time.Minute); err != nil {
		t.Fatalf("docker.WaitForOutput() timeout: %v", err)
	}

	client := testutil.MakeDocker("mysql-client-test")
	dir, err := testutil.PrepareFiles("mysql.sql")
	if err != nil {
		t.Fatalf("PrepareFiles() failed: %v", err)
	}

	// Tell mysql client to connect to the server and execute the file in verbose
	// mode to verify the output.
	args := []string{
		testutil.LinkArg(&d, "mysql"),
		testutil.MountArg(dir, "/sql", testutil.ReadWrite),
		"mysql",
		"mysql", "-hmysql", "-uroot", "-pfoobar123", "-v", "-e", "source /sql/mysql.sql",
	}
	if err := client.Run(args...); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer client.CleanUp()

	// Ensure file executed to the end and shutdown mysql.
	if _, err := client.WaitForOutput("--------------\nshutdown\n--------------", 15*time.Second); err != nil {
		t.Fatalf("docker.WaitForOutput() timeout: %v", err)
	}
	if _, err := d.WaitForOutput("mysqld: Shutdown complete", 30*time.Second); err != nil {
		t.Fatalf("docker.WaitForOutput() timeout: %v", err)
	}
}

func TestPythonHello(t *testing.T) {
	if err := testutil.Pull("google/python-hello"); err != nil {
		t.Fatalf("docker pull failed: %v", err)
	}
	d := testutil.MakeDocker("python-hello-test")
	if err := d.Run("-p", "8080", "google/python-hello"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer d.CleanUp()

	// Find where port 8080 is mapped to.
	port, err := d.FindPort(8080)
	if err != nil {
		t.Fatalf("docker.FindPort(8080) failed: %v", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(port, 30*time.Second); err != nil {
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

func TestTomcat(t *testing.T) {
	if err := testutil.Pull("tomcat:8.0"); err != nil {
		t.Fatalf("docker pull failed: %v", err)
	}
	d := testutil.MakeDocker("tomcat-test")
	if err := d.Run("-p", "8080", "tomcat:8.0"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer d.CleanUp()

	// Find where port 8080 is mapped to.
	port, err := d.FindPort(8080)
	if err != nil {
		t.Fatalf("docker.FindPort(8080) failed: %v", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(port, 30*time.Second); err != nil {
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
	if err := testutil.Pull("ruby"); err != nil {
		t.Fatalf("docker pull failed: %v", err)
	}
	d := testutil.MakeDocker("ruby-test")

	dir, err := testutil.PrepareFiles("ruby.rb", "ruby.sh")
	if err != nil {
		t.Fatalf("PrepareFiles() failed: %v", err)
	}
	if err := os.Chmod(filepath.Join(dir, "ruby.sh"), 0333); err != nil {
		t.Fatalf("os.Chmod(%q, 0333) failed: %v", dir, err)
	}

	if err := d.Run("-p", "8080", testutil.MountArg(dir, "/src", testutil.ReadOnly), "ruby", "/src/ruby.sh"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer d.CleanUp()

	// Find where port 8080 is mapped to.
	port, err := d.FindPort(8080)
	if err != nil {
		t.Fatalf("docker.FindPort(8080) failed: %v", err)
	}

	// Wait until it's up and running, 'gem install' can take some time.
	if err := testutil.WaitForHTTP(port, 1*time.Minute); err != nil {
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
	if err := testutil.Pull("alpine"); err != nil {
		t.Fatalf("docker pull failed: %v", err)
	}
	d := testutil.MakeDocker("stdio-test")

	wantStdout := "hello stdout"
	wantStderr := "bonjour stderr"
	cmd := fmt.Sprintf("echo %q; echo %q 1>&2;", wantStdout, wantStderr)
	if err := d.Run("alpine", "/bin/sh", "-c", cmd); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer d.CleanUp()

	for _, want := range []string{wantStdout, wantStderr} {
		if _, err := d.WaitForOutput(want, 5*time.Second); err != nil {
			t.Fatalf("docker didn't get output %q : %v", want, err)
		}
	}
}

func TestMain(m *testing.M) {
	testutil.EnsureSupportedDockerVersion()
	os.Exit(m.Run())
}
