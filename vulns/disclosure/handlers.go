// vulns/disclosure/handlers.go
package disclosure

import (
	"fmt"
	"net/http"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		// Private IP Disclosure
		handlers.Handle("/vulns/disclosure/private-ip", privateIP)
		handlers.Handle("/vulns/disclosure/private-ip/header", privateIPHeader)

		// Private Key Disclosure
		handlers.Handle("/vulns/disclosure/private-key/rsa", rsaKey)
		handlers.Handle("/vulns/disclosure/private-key/ssh", sshKey)
		handlers.Handle("/vulns/disclosure/private-key/pem", pemKey)

		// JWT Key Disclosure
		handlers.Handle("/vulns/disclosure/jwt-key", jwtKey)

		// PII Disclosure
		handlers.Handle("/vulns/disclosure/ssn", ssn)
		handlers.Handle("/vulns/disclosure/credit-card", creditCard)
		handlers.Handle("/vulns/disclosure/email", email)

		// Database Connection String
		handlers.Handle("/vulns/disclosure/db-connection", dbConnection)
		handlers.Handle("/vulns/disclosure/db-connection/env", dbConnectionEnv)

		// Directory Listing
		handlers.Handle("/vulns/disclosure/directory-listing", directoryListing)
		handlers.Handle("/vulns/disclosure/directory-listing/apache", apacheListing)
		handlers.Handle("/vulns/disclosure/directory-listing/nginx", nginxListing)

		// False positives
		handlers.Handle("/vulns/disclosure/fp/redacted", fpRedacted)
	})
}

func privateIP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Private IP Disclosure</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Private IP Address Disclosure</h1>
<p>Internal network information exposed in page content.</p>

<h2>Server Information:</h2>
<pre>
Application Server: 192.168.1.100
Database Server: 10.0.0.50
Cache Server: 172.16.0.25
Load Balancer: 192.168.1.1
</pre>

<h2>Debug Info:</h2>
<pre>
Client connected from: %s
Internal routing: 10.0.0.1 -> 10.0.0.50
</pre>

<p><a href="/vulns/disclosure/">Back to Disclosure Tests</a></p>
</div>
</body></html>`, r.RemoteAddr)
}

func privateIPHeader(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Private IPs in headers
	w.Header().Set("X-Backend-Server", "192.168.1.100")
	w.Header().Set("X-Database-Host", "10.0.0.50:3306")
	w.Header().Set("X-Cache-Server", "172.16.0.25")
	w.Header().Set("Content-Type", "text/html")

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Private IP in Headers</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Private IP Address in Headers</h1>
<p>Check the response headers for internal IP addresses.</p>

<h2>Response Headers:</h2>
<pre>
X-Backend-Server: 192.168.1.100
X-Database-Host: 10.0.0.50:3306
X-Cache-Server: 172.16.0.25
</pre>

<p><a href="/vulns/disclosure/">Back to Disclosure Tests</a></p>
</div>
</body></html>`)
}

func rsaKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>RSA Private Key Disclosure</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>RSA Private Key Disclosure</h1>
<p>Private RSA key exposed in page content.</p>

<h2>Configuration:</h2>
<pre>
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2Z3qX2BTLS4e0ek55tBjEZKvEeIT4bLzpnQbQnANgk9xXxmT
JOmFbOxzEb0xGVqHFDBNE4YkjGZKVPc6vVnL5qKpUxqK7B6sDfQS7RCxe9gqJZ8P
2v7K7N3VBXyPtE7hyE3G+7o3Q8Xz2PHFiXoJN6gq7W3gHDYw5Y3P0V7UKJdjJdBa
pXBQjNtLmexghjRNRb3EqTbP4dSUQXpSRQ/lppBKkJEqf3sNd2Y3VsNejseGZAME
8S7P7MrCRy6sBQwKCh/ERQQM8VCfE0nBA6bKm3HrBrEJHDpHtXOL5ymOxQCfpDaD
OZSCPKD9hGmXnpaBG0YdBPOXP6U7J9hxiT0WcwIDAQABAoIBAC5RgZ+hBx7xHnFZ
nQmZ3d9xJXgqq7K8NqPdFKuc9a4VPpB3lKHFzPTbWHM8e5hWizP7veocBrN7BxGk
5DyFQw7J7AYg8jXi0dRFtCpqF7JDfmKe3mXqX3vPf5e0nq9rPmE9jbu4zzidWWL3
-----END RSA PRIVATE KEY-----
</pre>

<p><a href="/vulns/disclosure/">Back to Disclosure Tests</a></p>
</div>
</body></html>`)
}

func sshKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SSH Private Key Disclosure</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>SSH Private Key Disclosure</h1>
<p>SSH private key exposed in application.</p>

<h2>Deployment Key:</h2>
<pre>
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBHK2Ow6D4M6ePCqvT9RM7l4fLZmUUcOQvLt3p7N5Xr9QAAAJhBvkN/Qb5D
fwAAAAtzc2gtZWQyNTUxOQAAACBHK2Ow6D4M6ePCqvT9RM7l4fLZmUUcOQvLt3p7N5Xr9Q
AAAEDDzwLxRlFbLl7AN3E4eNKrkeQ9eyPt8LyeMdy9nNy9Hy0rY7DoPgzp48Kq9P1EzuXh
8tmZRRw5C8u3ens3lev1AAAADWRlcGxveUBzZXJ2ZXI=
-----END OPENSSH PRIVATE KEY-----
</pre>

<p><a href="/vulns/disclosure/">Back to Disclosure Tests</a></p>
</div>
</body></html>`)
}

func pemKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>PEM Private Key Disclosure</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>PEM Private Key Disclosure</h1>
<p>PEM-encoded private key in application response.</p>

<h2>TLS Certificate Key:</h2>
<pre>
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5hZ6WhzdpYc8i
lBNkXuRYfkSFX8KjNJCLYqxNxHPD7cGENPDsmX7XYy3PV6MxKNT3NxK2xJpXpCdP
nxNBJXx7Qwe9nZnQGH3fKKe7TpRR4+mJbChPYHY3CnNqemAH0xeGPNT/HpPXfEIZ
-----END PRIVATE KEY-----
</pre>

<p><a href="/vulns/disclosure/">Back to Disclosure Tests</a></p>
</div>
</body></html>`)
}

func jwtKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>JWT Private Key Disclosure</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>JWT Private Key Disclosure</h1>
<p>JWT signing key exposed in application configuration.</p>

<h2>JWT Configuration:</h2>
<pre>
{
  "jwt": {
    "algorithm": "RS256",
    "privateKey": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA2Z3qX2BTLS4e0ek55tBjEZKvEeIT4bLzpnQbQnANgk9xXxmT\nJOmFbOxzEb0xGVqHFDBNE4YkjGZKVPc6vVnL5qKpUxqK7B6sDfQS7RCxe9gqJZ8P\n-----END RSA PRIVATE KEY-----",
    "publicKey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2Z3qX2BTLS4e0ek55tBj\n-----END PUBLIC KEY-----",
    "secret": "super-secret-jwt-key-12345",
    "expiresIn": "24h"
  }
}
</pre>

<h2>Environment Variables:</h2>
<pre>
JWT_SECRET=super-secret-jwt-key-12345
JWT_PRIVATE_KEY_PATH=/etc/ssl/jwt/private.pem
</pre>

<p><a href="/vulns/disclosure/">Back to Disclosure Tests</a></p>
</div>
</body></html>`)
}

func ssn(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SSN Disclosure</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Social Security Number Disclosure</h1>
<p>SSN exposed in application response.</p>

<h2>User Profile:</h2>
<pre>
Name: John Doe
Email: john.doe@example.com
SSN: 123-45-6789
Date of Birth: 1985-03-15
Address: 123 Main St, Anytown, USA
</pre>

<h2>Debug Log:</h2>
<pre>
[DEBUG] Processing user SSN: 987-65-4321
[DEBUG] Validating SSN format: 111-22-3333
</pre>

<p><a href="/vulns/disclosure/">Back to Disclosure Tests</a></p>
</div>
</body></html>`)
}

func creditCard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Credit Card Disclosure</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Credit Card Number Disclosure</h1>
<p>Credit card numbers exposed in application.</p>

<h2>Payment History:</h2>
<pre>
Order #12345
Card: 4111-1111-1111-1111
Expiry: 12/25
Amount: $99.99

Order #12346
Card: 5500-0000-0000-0004
Expiry: 06/26
Amount: $149.99
</pre>

<h2>Debug Output:</h2>
<pre>
Processing payment with card: 4242424242424242
CVV validation for: 378282246310005
</pre>

<p><a href="/vulns/disclosure/">Back to Disclosure Tests</a></p>
</div>
</body></html>`)
}

func email(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Email Address Disclosure</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Email Address Disclosure</h1>
<p>Internal email addresses exposed.</p>

<h2>Team Directory:</h2>
<pre>
admin@internal.company.com
root@server.internal
deploy@ci.internal.company.com
database-admin@internal.company.com
security-team@internal.company.com
</pre>

<h2>Error Messages:</h2>
<pre>
Failed to send notification to: alerts@internal.company.com
Backup notification sent to: backup-admin@internal.company.com
</pre>

<p><a href="/vulns/disclosure/">Back to Disclosure Tests</a></p>
</div>
</body></html>`)
}

func dbConnection(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Database Connection String Disclosure</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Database Connection String Disclosure</h1>
<p>Database credentials exposed in application.</p>

<h2>Configuration File:</h2>
<pre>
database:
  host: db.internal.company.com
  port: 3306
  username: app_user
  password: SuperSecretP@ssw0rd!
  database: production_db

redis:
  host: redis.internal.company.com
  port: 6379
  password: redis_secret_123
</pre>

<h2>Connection Strings:</h2>
<pre>
mysql://app_user:SuperSecretP@ssw0rd!@db.internal.company.com:3306/production_db
postgresql://admin:postgres_pass_456@10.0.0.50:5432/app_database
mongodb://mongo_user:mongo_pass@mongodb.internal:27017/app?authSource=admin
</pre>

<p><a href="/vulns/disclosure/">Back to Disclosure Tests</a></p>
</div>
</body></html>`)
}

func dbConnectionEnv(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Database Connection in Environment</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Database Connection String in Environment</h1>
<p>Database credentials in environment variables.</p>

<h2>Environment Variables:</h2>
<pre>
DATABASE_URL=mysql://root:password123@localhost:3306/myapp
REDIS_URL=redis://:redis_password@redis.local:6379/0
MONGODB_URI=mongodb://admin:mongodb_pass@mongo.local:27017/production
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
</pre>

<p><a href="/vulns/disclosure/">Back to Disclosure Tests</a></p>
</div>
</body></html>`)
}

func directoryListing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Directory Listing</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Index of /uploads/</h1>
<pre>
<a href="../">../</a>
<a href="backup.sql">backup.sql</a>                 2026-01-30 10:00   15M
<a href="config.php.bak">config.php.bak</a>             2026-01-29 15:30   2.5K
<a href="database_dump.sql">database_dump.sql</a>          2026-01-28 09:00   50M
<a href="private_keys/">private_keys/</a>              2026-01-27 12:00   -
<a href="user_data.csv">user_data.csv</a>              2026-01-26 14:00   1.2M
<a href=".env">.env</a>                       2026-01-25 08:00   512
<a href=".git/">.git/</a>                      2026-01-24 16:00   -
</pre>
<hr>
<p><a href="/vulns/disclosure/">Back to Disclosure Tests</a></p>
</div>
</body></html>`)
}

func apacheListing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Index of /var/www/html/uploads</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Index of /var/www/html/uploads</h1>
<table>
<tr><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th></tr>
<tr><th colspan="3"><hr></th></tr>
<tr><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td>-</td></tr>
<tr><td><a href="admin/">admin/</a></td><td>2026-01-30 10:00</td><td>-</td></tr>
<tr><td><a href="backup/">backup/</a></td><td>2026-01-29 15:30</td><td>-</td></tr>
<tr><td><a href="config.php">config.php</a></td><td>2026-01-28 09:00</td><td>2.5K</td></tr>
<tr><td><a href="wp-config.php.bak">wp-config.php.bak</a></td><td>2026-01-27 12:00</td><td>3.1K</td></tr>
<tr><th colspan="3"><hr></th></tr>
</table>
<address>Apache/2.4.52 (Ubuntu) Server at localhost Port 80</address>
</div>
</body></html>`)
}

func nginxListing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<html>
<head><title>Index of /data/</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Index of /data/</h1><hr><pre>
<a href="../">../</a>
<a href="api_keys.json">api_keys.json</a>                                      30-Jan-2026 10:00                1024
<a href="credentials.txt">credentials.txt</a>                                    29-Jan-2026 15:30                 512
<a href="database/">database/</a>                                          28-Jan-2026 09:00                   -
<a href="logs/">logs/</a>                                              27-Jan-2026 12:00                   -
<a href="secrets.yml">secrets.yml</a>                                        26-Jan-2026 14:00                2048
</pre><hr>
</div>
</body></html>`)
}

func fpRedacted(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Information Disclosure - Safe</title>
<link rel="stylesheet" href="/static/css/hive.css">
</head>
<body>
<div class="container">
<h1>Information Disclosure - Safe (Redacted)</h1>
<p>Sensitive information is properly redacted.</p>

<h2>User Profile:</h2>
<pre>
Name: John Doe
Email: j***@example.com
SSN: ***-**-6789
Card: ****-****-****-1111
</pre>

<h2>Server Info:</h2>
<pre>
Server: [REDACTED]
Database: [REDACTED]
</pre>

<h3>Security:</h3>
<p><small>SAFE: Sensitive data is masked/redacted before display</small></p>
<p><a href="/vulns/disclosure/">Back to Disclosure Tests</a></p>
</div>
</body></html>`)
}
