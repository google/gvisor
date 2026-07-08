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

// Package nextcloud is a gVisor compatibility test for Nextcloud backed by
// MariaDB.
//
// The version under test is pinned in
// images/compatibility/nextcloud/nextcloud/Dockerfile.
package nextcloud

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/compatibility"
)

const (
	nextcloudImage = "compatibility/nextcloud/nextcloud"
	mariadbImage   = "compatibility/nextcloud/mariadb"

	dbName     = "nextcloud"
	dbUser     = "nextcloud"
	dbPassword = "ncpass"
	dbRootPass = "rootpass"

	adminUser     = "admin"
	adminPassword = "Gvisor-Test-1234"

	trustedHost   = "localhost"
	nextcloudPort = 80

	readyTimeout = 5 * time.Minute // Nextcloud's first-run install is slow.
	pollInterval = 2 * time.Second
)

func TestNextcloud(t *testing.T) {
	ctx := context.Background()

	// MariaDB backend.
	db := dockerutil.MakeContainer(ctx, t)
	defer db.CleanUp(ctx)
	if err := db.Spawn(ctx, dockerutil.RunOpts{
		Image: mariadbImage,
		Env: []string{
			"MARIADB_ROOT_PASSWORD=" + dbRootPass,
			"MARIADB_DATABASE=" + dbName,
			"MARIADB_USER=" + dbUser,
			"MARIADB_PASSWORD=" + dbPassword,
		},
	}); err != nil {
		t.Fatalf("failed to start mariadb: %v", err)
	}

	// Wait until MariaDB is ready.
	compatibility.Poll(ctx, t, "mariadb to accept queries", readyTimeout, pollInterval, func() error {
		out, err := db.Exec(ctx, dockerutil.ExecOpts{},
			"mariadb", "-u"+dbUser, "-p"+dbPassword, dbName, "-e", "SELECT 1")
		if err != nil {
			return fmt.Errorf("mariadb query: %v (%s)", err, out)
		}
		return nil
	})

	// Nextcloud, linked to MariaDB.
	// Admin + DB env trigger Nextcloud's unattended install on startup.
	app := dockerutil.MakeContainer(ctx, t)
	defer app.CleanUp(ctx)
	if err := app.Spawn(ctx, dockerutil.RunOpts{
		Image: nextcloudImage,
		Links: []string{db.MakeLink("db")},
		Env: []string{
			"MYSQL_HOST=db",
			"MYSQL_DATABASE=" + dbName,
			"MYSQL_USER=" + dbUser,
			"MYSQL_PASSWORD=" + dbPassword,
			"NEXTCLOUD_ADMIN_USER=" + adminUser,
			"NEXTCLOUD_ADMIN_PASSWORD=" + adminPassword,
			"NEXTCLOUD_TRUSTED_DOMAINS=" + trustedHost,
		},
	}); err != nil {
		t.Fatalf("failed to start nextcloud: %v", err)
	}

	ip, err := app.FindIP(ctx, false)
	if err != nil {
		t.Fatalf("failed to find nextcloud IP: %v", err)
	}
	base := fmt.Sprintf("http://%s:%d", ip.String(), nextcloudPort)

	// Wait for the unattended install to finish.
	compatibility.Poll(ctx, t, "nextcloud install to finish", readyTimeout, pollInterval, func() error {
		status, body, err := compatibility.Request{URL: base + "/status.php", Host: trustedHost}.Do()
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("GET /status.php: status %d (%s)", status, body)
		}
		if !strings.Contains(body, `"installed":true`) {
			return fmt.Errorf("not installed yet: %s", body)
		}
		return nil
	})

	// OCS API: fetch the current user.
	if body := (compatibility.Request{
		URL:      base + "/ocs/v1.php/cloud/user?format=json",
		Host:     trustedHost,
		Username: adminUser,
		Password: adminPassword,
		Headers:  map[string]string{"OCS-APIRequest": "true"},
	}).DoOrFatal(t, http.StatusOK); !strings.Contains(body, `"id":"`+adminUser+`"`) {
		t.Fatalf("OCS user: response missing admin id; got: %s", body)
	}

	// WebDAV: upload a file, then download it and verify the content round-trips.
	const content = "hello from the gVisor nextcloud compatibility test"
	davURL := base + "/remote.php/dav/files/" + adminUser + "/gvtest.txt"
	compatibility.Request{
		Method:   http.MethodPut,
		URL:      davURL,
		Body:     content,
		Host:     trustedHost,
		Username: adminUser,
		Password: adminPassword,
	}.DoOrFatal(t, http.StatusCreated)
	if got := (compatibility.Request{
		URL:      davURL,
		Host:     trustedHost,
		Username: adminUser,
		Password: adminPassword,
	}).DoOrFatal(t, http.StatusOK); got != content {
		t.Fatalf("WebDAV round-trip: got %q, want %q", got, content)
	}
}

func TestMain(m *testing.M) {
	dockerutil.EnsureSupportedDockerVersion()
	flag.Parse()
	os.Exit(m.Run())
}
