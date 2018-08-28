// Copyright 2018 Google Inc.
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

// Package image provides end-to-end image tests for runsc. These tests require
// docker and runsc to be installed on the machine. To set it up, run:
//
//     ./runsc/test/install.sh [--runtime <name>]
//
// The tests expect the runtime name to be provided in the RUNSC_RUNTIME
// environment variable (default: runsc-test).
//
// Each test calls docker commands to start up a container, and tests that it is
// behaving properly, like connecting to a port or looking at the output. The
// container is killed and deleted at the end.
package image

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"gvisor.googlesource.com/gvisor/runsc/test/testutil"
)

func TestHelloWorld(t *testing.T) {
	d := testutil.MakeDocker("hello-test")
	if _, err := d.Run("hello-world"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer d.CleanUp()

	if err := d.WaitForOutput("Hello from Docker!", 5*time.Second); err != nil {
		t.Fatalf("docker didn't say hello: %v", err)
	}
}

func testHTTPServer(port int) error {
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
	if _, err := d.Run("-p", "80", "-v", testutil.MountArg(dir, "/usr/local/apache2/htdocs:ro"), "httpd"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer d.CleanUp()

	// Find where port 80 is mapped to.
	port, err := d.FindPort(80)
	if err != nil {
		t.Fatalf("docker.FindPort(80) failed: %v", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(port, 5*time.Second); err != nil {
		t.Fatalf("WaitForHTTP() timeout: %v", err)
	}

	if err := testHTTPServer(port); err != nil {
		t.Fatalf("testHTTPServer(%d) failed: %v", port, err)
	}
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
	if _, err := d.Run("-p", "80", "-v", testutil.MountArg(dir, "/usr/share/nginx/html:ro"), "nginx"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer d.CleanUp()

	// Find where port 80 is mapped to.
	port, err := d.FindPort(80)
	if err != nil {
		t.Fatalf("docker.FindPort(80) failed: %v", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(port, 5*time.Second); err != nil {
		t.Fatalf("WaitForHTTP() timeout: %v", err)
	}

	if err := testHTTPServer(port); err != nil {
		t.Fatalf("testHTTPServer(%d) failed: %v", port, err)
	}
}

func TestMysql(t *testing.T) {
	if err := testutil.Pull("mysql"); err != nil {
		t.Fatalf("docker pull failed: %v", err)
	}
	d := testutil.MakeDocker("mysql-test")

	// Start the container.
	if _, err := d.Run("-e", "MYSQL_ROOT_PASSWORD=foobar123", "mysql"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer d.CleanUp()

	// Wait until it's up and running.
	if err := d.WaitForOutput("port: 3306  MySQL Community Server", 3*time.Minute); err != nil {
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
		"--link", testutil.LinkArg(&d, "mysql"),
		"-v", testutil.MountArg(dir, "/sql"),
		"mysql",
		"mysql", "-hmysql", "-uroot", "-pfoobar123", "-v", "-e", "source /sql/mysql.sql",
	}
	if _, err := client.Run(args...); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer client.CleanUp()

	// Ensure file executed to the end and shutdown mysql.
	if err := client.WaitForOutput("--------------\nshutdown\n--------------", 15*time.Second); err != nil {
		t.Fatalf("docker.WaitForOutput() timeout: %v", err)
	}
	if err := d.WaitForOutput("mysqld: Shutdown complete", 30*time.Second); err != nil {
		t.Fatalf("docker.WaitForOutput() timeout: %v", err)
	}
}

func TestPythonHello(t *testing.T) {
	if err := testutil.Pull("google/python-hello"); err != nil {
		t.Fatalf("docker pull failed: %v", err)
	}
	d := testutil.MakeDocker("python-hello-test")
	if _, err := d.Run("-p", "8080", "google/python-hello"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer d.CleanUp()

	// Find where port 8080 is mapped to.
	port, err := d.FindPort(8080)
	if err != nil {
		t.Fatalf("docker.FindPort(8080) failed: %v", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(port, 20*time.Second); err != nil {
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
	if _, err := d.Run("-p", "8080", "tomcat:8.0"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer d.CleanUp()

	// Find where port 8080 is mapped to.
	port, err := d.FindPort(8080)
	if err != nil {
		t.Fatalf("docker.FindPort(8080) failed: %v", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(port, 10*time.Second); err != nil {
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

func MainTest(m *testing.M) {
	testutil.EnsureSupportedDockerVersion()
	os.Exit(m.Run())
}
