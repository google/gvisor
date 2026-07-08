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

// Package wordpress is a gVisor compatibility test for WordPress backed by MySQL.
//
// The WordPress and MySQL versions under test are pinned in
// images/compatibility/wordpress/{wordpress,mysql}/Dockerfile.
package wordpress

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/compatibility"
)

const (
	wordpressImage = "compatibility/wordpress/wordpress"
	mysqlImage     = "compatibility/wordpress/mysql"

	dbName         = "wordpress"
	dbUser         = "wp"
	dbPassword     = "wppass"
	dbRootPassword = "rootpass"

	siteTitle     = "gVisor Compat Test"
	adminUser     = "gvisoradmin"
	adminPassword = "gvisor-Test-1234!"
	adminEmail    = "admin@example.com"

	wpPort = 80

	readyTimeout = 3 * time.Minute
	pollInterval = 2 * time.Second
)

func TestWordPress(t *testing.T) {
	ctx := context.Background()

	// MySQL backend.
	db := dockerutil.MakeContainer(ctx, t)
	defer db.CleanUp(ctx)
	if err := db.Spawn(ctx, dockerutil.RunOpts{
		Image: mysqlImage,
		Env: []string{
			"MYSQL_ROOT_PASSWORD=" + dbRootPassword,
			"MYSQL_DATABASE=" + dbName,
			"MYSQL_USER=" + dbUser,
			"MYSQL_PASSWORD=" + dbPassword,
		},
	}); err != nil {
		t.Fatalf("failed to start mysql: %v", err)
	}

	// Wait until the application user can run a query.
	compatibility.Poll(ctx, t, "mysql to accept queries", readyTimeout, pollInterval, func() error {
		out, err := db.Exec(ctx, dockerutil.ExecOpts{},
			"mysql", "-u"+dbUser, "-p"+dbPassword, dbName, "-e", "SELECT 1")
		if err != nil {
			return fmt.Errorf("mysql query: %v (%s)", err, out)
		}
		return nil
	})

	// WordPress app container.
	wp := dockerutil.MakeContainer(ctx, t)
	defer wp.CleanUp(ctx)
	if err := wp.Spawn(ctx, dockerutil.RunOpts{
		Image: wordpressImage,
		Links: []string{db.MakeLink("db")},
		Env: []string{
			"WORDPRESS_DB_HOST=db:3306",
			"WORDPRESS_DB_USER=" + dbUser,
			"WORDPRESS_DB_PASSWORD=" + dbPassword,
			"WORDPRESS_DB_NAME=" + dbName,
		},
	}); err != nil {
		t.Fatalf("failed to start wordpress: %v", err)
	}

	ip, err := wp.FindIP(ctx, false)
	if err != nil {
		t.Fatalf("failed to find wordpress IP: %v", err)
	}
	base := fmt.Sprintf("http://%s:%d", ip.String(), wpPort)

	// Wait for WordPress to serve the installer.
	compatibility.Poll(ctx, t, "wordpress installer to be ready", readyTimeout, pollInterval, func() error {
		status, _, err := compatibility.Get(base + "/wp-admin/install.php")
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("GET /wp-admin/install.php: status %d", status)
		}
		return nil
	})

	// Run the install.
	form := url.Values{
		"weblog_title":    {siteTitle},
		"user_name":       {adminUser},
		"admin_password":  {adminPassword},
		"admin_password2": {adminPassword},
		"pw_weak":         {"1"}, // acknowledge the password strength prompt.
		"admin_email":     {adminEmail},
		"blog_public":     {"1"},
		"language":        {""},
		"Submit":          {"Install WordPress"},
	}
	installed := compatibility.Request{
		Method:      http.MethodPost,
		URL:         base + "/wp-admin/install.php?step=2",
		ContentType: "application/x-www-form-urlencoded",
		Body:        form.Encode(),
	}.DoOrFatal(t, http.StatusOK)
	if !strings.Contains(installed, "Success") {
		t.Fatalf("install did not report success; body: %s", installed)
	}

	// The front page is rendered from the database: it must show the title we
	// just stored.
	front := compatibility.Request{URL: base + "/"}.DoOrFatal(t, http.StatusOK)
	if !strings.Contains(front, siteTitle) {
		t.Fatalf("front page missing site title %q; body: %s", siteTitle, front)
	}

	// The REST API reads the default seed post back out.
	posts := compatibility.Request{URL: base + "/?rest_route=/wp/v2/posts"}.DoOrFatal(t, http.StatusOK)
	if !strings.Contains(posts, "Hello world") {
		t.Fatalf("REST posts missing default seed post; body: %s", posts)
	}
	t.Logf("wordpress installed and serving %q from MySQL", siteTitle)
}

func TestMain(m *testing.M) {
	dockerutil.EnsureSupportedDockerVersion()
	flag.Parse()
	os.Exit(m.Run())
}
