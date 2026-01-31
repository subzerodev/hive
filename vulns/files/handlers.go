// vulns/files/handlers.go
package files

import (
	"fmt"
	"net/http"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		// Backup Files
		handlers.Handle("/vulns/files/backup/sql", backupSQL)
		handlers.Handle("/vulns/files/backup/config", backupConfig)
		handlers.Handle("/vulns/files/backup/archive", backupArchive)
		handlers.Handle("/vulns/files/backup/old", backupOld)

		// Common Sensitive Files
		handlers.Handle("/vulns/files/common/git-config", gitConfig)
		handlers.Handle("/vulns/files/common/git-head", gitHead)
		handlers.Handle("/vulns/files/common/env", envFile)
		handlers.Handle("/vulns/files/common/htaccess", htaccess)
		handlers.Handle("/vulns/files/common/htpasswd", htpasswd)
		handlers.Handle("/vulns/files/common/wp-config", wpConfig)
		handlers.Handle("/vulns/files/common/composer", composerJson)
		handlers.Handle("/vulns/files/common/package", packageJson)
		handlers.Handle("/vulns/files/common/docker-compose", dockerCompose)

		// Development Files
		handlers.Handle("/vulns/files/dev/phpinfo", phpinfo)
		handlers.Handle("/vulns/files/dev/debug", debugPage)
		handlers.Handle("/vulns/files/dev/test", testPage)

		// False positive
		handlers.Handle("/vulns/files/fp/protected", fpProtected)
	})
}

func backupSQL(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, `-- MySQL dump 10.13  Distrib 8.0.32
-- Host: localhost    Database: production
-- ------------------------------------------------------
-- Server version	8.0.32

DROP TABLE IF EXISTS users;
CREATE TABLE users (
  id int NOT NULL AUTO_INCREMENT,
  username varchar(50) NOT NULL,
  password_hash varchar(255) NOT NULL,
  email varchar(100) NOT NULL,
  PRIMARY KEY (id)
);

INSERT INTO users VALUES (1,'admin','$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.VTtYA','admin@example.com');
INSERT INTO users VALUES (2,'user1','$2a$12$WQv2e3yrBVVHykf0KGBjDPYz7TtxNQKrjM9/Y5.WUtZB','user1@example.com');

DROP TABLE IF EXISTS api_keys;
CREATE TABLE api_keys (
  id int NOT NULL AUTO_INCREMENT,
  user_id int NOT NULL,
  api_key varchar(64) NOT NULL,
  PRIMARY KEY (id)
);

INSERT INTO api_keys VALUES (1,1,'sk-prod-abc123def456ghi789jkl012mno345pqr678');
`)
}

func backupConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, `<?php
// config.php.bak - Backup created 2026-01-15

define('DB_HOST', 'db.internal.company.com');
define('DB_USER', 'app_user');
define('DB_PASS', 'SuperSecretPassword123!');
define('DB_NAME', 'production_database');

define('API_SECRET', 'sk-live-abc123def456ghi789');
define('ENCRYPTION_KEY', 'aes256-secret-key-do-not-share');

define('SMTP_HOST', 'smtp.company.com');
define('SMTP_USER', 'noreply@company.com');
define('SMTP_PASS', 'smtp_password_456');
?>
`)
}

func backupArchive(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Backup Archive Detected</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Backup Archive Files</h1>
<p>The following backup archives were detected:</p>

<h2>Available Backups:</h2>
<ul>
    <li><a href="/static/backup.zip">backup.zip</a> (15MB)</li>
    <li><a href="/static/backup.tar.gz">backup.tar.gz</a> (12MB)</li>
    <li><a href="/static/www.zip">www.zip</a> (8MB)</li>
    <li><a href="/static/site_backup_2026.zip">site_backup_2026.zip</a> (20MB)</li>
    <li><a href="/static/database.sql.gz">database.sql.gz</a> (5MB)</li>
</ul>

<p><a href="/vulns/files/">Back to Files Tests</a></p>
</div>
</body></html>`)
}

func backupOld(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, `# Old configuration file - index.php.old
<?php
// Legacy authentication - DO NOT USE IN PRODUCTION
$admin_password = "admin123";
$secret_key = "legacy-secret-key-12345";

// Old database credentials
$db_config = array(
    'host' => 'old-db.internal.com',
    'user' => 'legacy_user',
    'pass' => 'old_password_789',
    'name' => 'legacy_database'
);
?>
`)
}

func gitConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = git@github.com:company/private-repo.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
[user]
	name = Developer
	email = dev@company.com
`)
}

func gitHead(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, `ref: refs/heads/main
`)
}

func envFile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, `# Environment Configuration
APP_ENV=production
APP_DEBUG=false
APP_KEY=base64:dGhpcyBpcyBhIHNlY3JldCBrZXkgZG8gbm90IHNoYXJl

DB_CONNECTION=mysql
DB_HOST=db.internal.company.com
DB_PORT=3306
DB_DATABASE=production
DB_USERNAME=app_user
DB_PASSWORD=ProductionPassword123!

REDIS_HOST=redis.internal.company.com
REDIS_PASSWORD=redis_secret_key

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1

STRIPE_KEY=sk_live_abc123def456
STRIPE_SECRET=sk_live_xyz789abc012

JWT_SECRET=super-long-jwt-secret-key-for-signing-tokens
`)
}

func htaccess(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, `# Apache .htaccess file
RewriteEngine On
RewriteCond %%{HTTPS} off
RewriteRule ^(.*)$ https://%%{HTTP_HOST}%%{REQUEST_URI} [L,R=301]

# Protect sensitive directories
# Note: These rules may expose path structure
<FilesMatch "\.(sql|bak|old|log)$">
    Order Allow,Deny
    Deny from all
</FilesMatch>

# Basic auth for admin
AuthType Basic
AuthName "Admin Area"
AuthUserFile /var/www/.htpasswd
Require valid-user
`)
}

func htpasswd(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, `admin:$apr1$xyz12345$abcdefghijklmnopqrstuv
developer:$apr1$abc67890$uvwxyz1234567890abcdef
backup:$apr1$backup99$backuppasswordhashhere1
`)
}

func wpConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, `<?php
// wp-config.php - WordPress Configuration

define('DB_NAME', 'wordpress_production');
define('DB_USER', 'wp_admin');
define('DB_PASSWORD', 'WpSecureP@ssw0rd!');
define('DB_HOST', 'mysql.internal.company.com');

define('AUTH_KEY',         'put your unique phrase here');
define('SECURE_AUTH_KEY',  'put your unique phrase here');
define('LOGGED_IN_KEY',    'put your unique phrase here');
define('NONCE_KEY',        'put your unique phrase here');
define('AUTH_SALT',        'put your unique phrase here');

$table_prefix = 'wp_';
define('WP_DEBUG', false);

require_once(ABSPATH . 'wp-settings.php');
?>
`)
}

func composerJson(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
    "name": "company/private-app",
    "description": "Internal application",
    "require": {
        "php": ">=8.0",
        "laravel/framework": "^9.0",
        "company/private-package": "dev-main"
    },
    "repositories": [
        {
            "type": "vcs",
            "url": "git@github.com:company/private-package.git"
        }
    ],
    "config": {
        "github-oauth": {
            "github.com": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        }
    }
}
`)
}

func packageJson(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
  "name": "internal-app",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "dev": "npm run development",
    "build": "npm run production"
  },
  "dependencies": {
    "axios": "^0.21.1",
    "lodash": "^4.17.21"
  },
  "devDependencies": {
    "webpack": "^5.0.0"
  },
  "config": {
    "npm_token": "npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  }
}
`)
}

func dockerCompose(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/yaml")
	fmt.Fprintf(w, `version: '3.8'
services:
  app:
    build: .
    environment:
      - DB_HOST=db
      - DB_PASSWORD=docker_db_password_123
      - REDIS_PASSWORD=redis_secret
      - API_KEY=sk-live-production-key
    ports:
      - "80:80"
  db:
    image: mysql:8.0
    environment:
      - MYSQL_ROOT_PASSWORD=root_password_456
      - MYSQL_DATABASE=app
      - MYSQL_USER=app_user
      - MYSQL_PASSWORD=docker_db_password_123
  redis:
    image: redis:alpine
    command: redis-server --requirepass redis_secret
`)
}

func phpinfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>phpinfo()</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>PHP Version 8.1.0</h1>
<table>
<tr><td>System</td><td>Linux server 5.15.0 x86_64</td></tr>
<tr><td>Build Date</td><td>Jan 15 2026</td></tr>
<tr><td>Server API</td><td>Apache 2.0 Handler</td></tr>
<tr><td>Document Root</td><td>/var/www/html</td></tr>
<tr><td>Configuration File</td><td>/etc/php/8.1/apache2/php.ini</td></tr>
</table>
<h2>Environment</h2>
<table>
<tr><td>DB_PASSWORD</td><td>ProductionPassword123!</td></tr>
<tr><td>API_SECRET</td><td>sk-live-abc123def456</td></tr>
<tr><td>AWS_SECRET_ACCESS_KEY</td><td>wJalrXUtnFEMI/K7MDENG</td></tr>
</table>
<p><a href="/vulns/files/">Back to Files Tests</a></p>
</div>
</body></html>`)
}

func debugPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Debug Page</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Debug Information</h1>
<h2>Request Headers:</h2>
<pre>%v</pre>
<h2>Server Variables:</h2>
<pre>
DOCUMENT_ROOT: /var/www/html
SERVER_SOFTWARE: Apache/2.4.52
DB_CONNECTION: mysql://user:pass@localhost/db
INTERNAL_API_KEY: internal-debug-key-12345
</pre>
<p><a href="/vulns/files/">Back to Files Tests</a></p>
</div>
</body></html>`, r.Header)
}

func testPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Test Page</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Test/Development Page</h1>
<p>This is a test page that should not be accessible in production.</p>
<h2>Test Credentials:</h2>
<pre>
Admin: admin / admin123
Test: test / test123
Debug: debug / debug_pass
</pre>
<h2>Test API Keys:</h2>
<pre>
TEST_API_KEY=test-key-12345-abcdef
DEBUG_TOKEN=debug-token-67890-ghijkl
</pre>
<p><a href="/vulns/files/">Back to Files Tests</a></p>
</div>
</body></html>`)
}

func fpProtected(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusForbidden)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>403 Forbidden</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>403 Forbidden</h1>
<p>Access to this resource is denied.</p>
<h3>Security:</h3>
<p><small>SAFE: Sensitive files are protected with proper access controls</small></p>
<p><a href="/vulns/files/">Back to Files Tests</a></p>
</div>
</body></html>`)
}
