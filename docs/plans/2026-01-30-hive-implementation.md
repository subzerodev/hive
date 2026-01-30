# HIVE Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Go-based vulnerability testbed covering comprehensive web vulnerability categories for scanner validation.

**Architecture:** Single Go binary serving dynamic vulnerability endpoints and static files. Docker-compose orchestrates the app plus MySQL, PostgreSQL, and MSSQL databases. SQLite embedded. File-based convention for test cases with auto-discovery via Go's `init()` pattern.

**Tech Stack:** Go 1.21+, net/http, database/sql, Docker, MySQL 8, PostgreSQL 15, MSSQL 2022, SQLite

---

## Phase 1: Core Infrastructure

### Task 1.1: Initialize Go Module

**Files:**
- Create: `go.mod`
- Create: `main.go`

**Step 1: Initialize go module**

```bash
cd /home/wheatly/workspace/hive
go mod init github.com/subzerodev/hive
```

**Step 2: Create minimal main.go**

```go
// main.go
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("HIVE starting on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}
```

**Step 3: Verify it compiles**

```bash
go build -o hive .
```

Expected: Binary `hive` created with no errors.

**Step 4: Commit**

```bash
git add go.mod main.go
git commit -m "feat: initialize Go module and minimal server"
```

---

### Task 1.2: Add Health Endpoint

**Files:**
- Modify: `main.go`

**Step 1: Add health handler before ListenAndServe**

```go
// main.go - add before ListenAndServe call
http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"healthy"}`))
})
```

**Step 2: Test manually**

```bash
go run . &
curl http://localhost:8080/health
kill %1
```

Expected: `{"status":"healthy"}`

**Step 3: Commit**

```bash
git add main.go
git commit -m "feat: add /health endpoint"
```

---

### Task 1.3: Create Dockerfile

**Files:**
- Create: `Dockerfile`

**Step 1: Create multi-stage Dockerfile**

```dockerfile
# Dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o hive .

FROM alpine:3.19

RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /app/hive .
COPY static/ ./static/
COPY vulns/ ./vulns/

EXPOSE 8080
CMD ["./hive"]
```

**Step 2: Create placeholder directories**

```bash
mkdir -p static vulns
touch static/.gitkeep vulns/.gitkeep
```

**Step 3: Test Docker build**

```bash
docker build -t hive:dev .
```

Expected: Build completes successfully.

**Step 4: Commit**

```bash
git add Dockerfile static/.gitkeep vulns/.gitkeep
git commit -m "feat: add Dockerfile with multi-stage build"
```

---

### Task 1.4: Create Docker Compose with Databases

**Files:**
- Create: `docker-compose.yml`

**Step 1: Create docker-compose.yml**

```yaml
# docker-compose.yml
services:
  hive:
    build: .
    ports:
      - "8080:8080"
    environment:
      - PORT=8080
      - AUTH_TYPE=none
      - MYSQL_DSN=root:hive@tcp(mysql:3306)/hive
      - POSTGRES_DSN=postgres://postgres:hive@postgres:5432/hive?sslmode=disable
      - MSSQL_DSN=sqlserver://sa:Hive_Password1@mssql:1433?database=hive
      - SQLITE_PATH=/app/data/hive.db
    volumes:
      - sqlite-data:/app/data
    depends_on:
      mysql:
        condition: service_healthy
      postgres:
        condition: service_healthy
      mssql:
        condition: service_started

  mysql:
    image: mysql:8
    environment:
      MYSQL_ROOT_PASSWORD: hive
      MYSQL_DATABASE: hive
    volumes:
      - ./seed/mysql.sql:/docker-entrypoint-initdb.d/init.sql
      - mysql-data:/var/lib/mysql
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      interval: 5s
      timeout: 5s
      retries: 10

  postgres:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: hive
      POSTGRES_DB: hive
    volumes:
      - ./seed/postgres.sql:/docker-entrypoint-initdb.d/init.sql
      - postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 10

  mssql:
    image: mcr.microsoft.com/mssql/server:2022-latest
    environment:
      ACCEPT_EULA: Y
      SA_PASSWORD: Hive_Password1
    volumes:
      - ./seed/mssql.sql:/seed.sql
      - mssql-data:/var/opt/mssql

volumes:
  mysql-data:
  postgres-data:
  mssql-data:
  sqlite-data:
```

**Step 2: Create seed directory**

```bash
mkdir -p seed
```

**Step 3: Commit**

```bash
git add docker-compose.yml seed
git commit -m "feat: add docker-compose with MySQL, PostgreSQL, MSSQL"
```

---

### Task 1.5: Create Database Seed Files

**Files:**
- Create: `seed/mysql.sql`
- Create: `seed/postgres.sql`
- Create: `seed/mssql.sql`
- Create: `seed/sqlite.sql`

**Step 1: Create MySQL seed**

```sql
-- seed/mysql.sql
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL,
    role VARCHAR(20) DEFAULT 'user'
);

CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL
);

CREATE TABLE IF NOT EXISTS comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (username, password, email, role) VALUES
    ('admin', 'password', 'admin@hive.local', 'admin'),
    ('user1', 'pass123', 'user1@hive.local', 'user'),
    ('user2', 'pass456', 'user2@hive.local', 'user');

INSERT INTO products (name, description, price) VALUES
    ('Widget A', 'A standard widget', 19.99),
    ('Widget B', 'A premium widget', 49.99),
    ('Gadget X', 'An advanced gadget', 99.99);

INSERT INTO comments (user_id, content) VALUES
    (1, 'Welcome to HIVE!'),
    (2, 'This is a test comment'),
    (3, 'Another comment here');
```

**Step 2: Create PostgreSQL seed**

```sql
-- seed/postgres.sql
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL,
    role VARCHAR(20) DEFAULT 'user'
);

CREATE TABLE IF NOT EXISTS products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL
);

CREATE TABLE IF NOT EXISTS comments (
    id SERIAL PRIMARY KEY,
    user_id INT,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (username, password, email, role) VALUES
    ('admin', 'password', 'admin@hive.local', 'admin'),
    ('user1', 'pass123', 'user1@hive.local', 'user'),
    ('user2', 'pass456', 'user2@hive.local', 'user');

INSERT INTO products (name, description, price) VALUES
    ('Widget A', 'A standard widget', 19.99),
    ('Widget B', 'A premium widget', 49.99),
    ('Gadget X', 'An advanced gadget', 99.99);

INSERT INTO comments (user_id, content) VALUES
    (1, 'Welcome to HIVE!'),
    (2, 'This is a test comment'),
    (3, 'Another comment here');
```

**Step 3: Create MSSQL seed**

```sql
-- seed/mssql.sql
IF NOT EXISTS (SELECT * FROM sys.databases WHERE name = 'hive')
BEGIN
    CREATE DATABASE hive;
END;
GO

USE hive;
GO

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'users')
BEGIN
    CREATE TABLE users (
        id INT IDENTITY(1,1) PRIMARY KEY,
        username VARCHAR(50) NOT NULL,
        password VARCHAR(100) NOT NULL,
        email VARCHAR(100) NOT NULL,
        role VARCHAR(20) DEFAULT 'user'
    );
END;
GO

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'products')
BEGIN
    CREATE TABLE products (
        id INT IDENTITY(1,1) PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        description TEXT,
        price DECIMAL(10,2) NOT NULL
    );
END;
GO

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'comments')
BEGIN
    CREATE TABLE comments (
        id INT IDENTITY(1,1) PRIMARY KEY,
        user_id INT,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT GETDATE()
    );
END;
GO

INSERT INTO users (username, password, email, role) VALUES
    ('admin', 'password', 'admin@hive.local', 'admin'),
    ('user1', 'pass123', 'user1@hive.local', 'user'),
    ('user2', 'pass456', 'user2@hive.local', 'user');
GO

INSERT INTO products (name, description, price) VALUES
    ('Widget A', 'A standard widget', 19.99),
    ('Widget B', 'A premium widget', 49.99),
    ('Gadget X', 'An advanced gadget', 99.99);
GO

INSERT INTO comments (user_id, content) VALUES
    (1, 'Welcome to HIVE!'),
    (2, 'This is a test comment'),
    (3, 'Another comment here');
GO
```

**Step 4: Create SQLite seed**

```sql
-- seed/sqlite.sql
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    email TEXT NOT NULL,
    role TEXT DEFAULT 'user'
);

CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    price REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (username, password, email, role) VALUES
    ('admin', 'password', 'admin@hive.local', 'admin'),
    ('user1', 'pass123', 'user1@hive.local', 'user'),
    ('user2', 'pass456', 'user2@hive.local', 'user');

INSERT INTO products (name, description, price) VALUES
    ('Widget A', 'A standard widget', 19.99),
    ('Widget B', 'A premium widget', 49.99),
    ('Gadget X', 'An advanced gadget', 99.99);

INSERT INTO comments (user_id, content) VALUES
    (1, 'Welcome to HIVE!'),
    (2, 'This is a test comment'),
    (3, 'Another comment here');
```

**Step 5: Commit**

```bash
git add seed/
git commit -m "feat: add database seed files for all databases"
```

---

### Task 1.6: Add Database Connection Package

**Files:**
- Create: `db/db.go`
- Modify: `go.mod` (via go get)

**Step 1: Install database drivers**

```bash
cd /home/wheatly/workspace/hive
go get github.com/go-sql-driver/mysql
go get github.com/lib/pq
go get github.com/microsoft/go-mssqldb
go get github.com/mattn/go-sqlite3
```

**Step 2: Create db package**

```go
// db/db.go
package db

import (
	"database/sql"
	"log"
	"os"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	_ "github.com/microsoft/go-mssqldb"
)

var (
	MySQL    *sql.DB
	Postgres *sql.DB
	MSSQL    *sql.DB
	SQLite   *sql.DB
)

func Init() {
	var err error

	// MySQL
	if dsn := os.Getenv("MYSQL_DSN"); dsn != "" {
		MySQL, err = sql.Open("mysql", dsn)
		if err != nil {
			log.Printf("MySQL connection error: %v", err)
		} else if err = MySQL.Ping(); err != nil {
			log.Printf("MySQL ping error: %v", err)
		} else {
			log.Println("MySQL connected")
		}
	}

	// PostgreSQL
	if dsn := os.Getenv("POSTGRES_DSN"); dsn != "" {
		Postgres, err = sql.Open("postgres", dsn)
		if err != nil {
			log.Printf("PostgreSQL connection error: %v", err)
		} else if err = Postgres.Ping(); err != nil {
			log.Printf("PostgreSQL ping error: %v", err)
		} else {
			log.Println("PostgreSQL connected")
		}
	}

	// MSSQL
	if dsn := os.Getenv("MSSQL_DSN"); dsn != "" {
		MSSQL, err = sql.Open("sqlserver", dsn)
		if err != nil {
			log.Printf("MSSQL connection error: %v", err)
		} else if err = MSSQL.Ping(); err != nil {
			log.Printf("MSSQL ping error: %v", err)
		} else {
			log.Println("MSSQL connected")
		}
	}

	// SQLite
	sqlitePath := os.Getenv("SQLITE_PATH")
	if sqlitePath == "" {
		sqlitePath = "./hive.db"
	}
	SQLite, err = sql.Open("sqlite3", sqlitePath)
	if err != nil {
		log.Printf("SQLite connection error: %v", err)
	} else {
		log.Println("SQLite connected")
		initSQLite()
	}
}

func initSQLite() {
	// Create tables if they don't exist
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		password TEXT NOT NULL,
		email TEXT NOT NULL,
		role TEXT DEFAULT 'user'
	);
	CREATE TABLE IF NOT EXISTS products (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT,
		price REAL NOT NULL
	);
	CREATE TABLE IF NOT EXISTS comments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER,
		content TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`
	if _, err := SQLite.Exec(schema); err != nil {
		log.Printf("SQLite schema error: %v", err)
	}

	// Seed if empty
	var count int
	SQLite.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if count == 0 {
		seed := `
		INSERT INTO users (username, password, email, role) VALUES
			('admin', 'password', 'admin@hive.local', 'admin'),
			('user1', 'pass123', 'user1@hive.local', 'user'),
			('user2', 'pass456', 'user2@hive.local', 'user');
		INSERT INTO products (name, description, price) VALUES
			('Widget A', 'A standard widget', 19.99),
			('Widget B', 'A premium widget', 49.99),
			('Gadget X', 'An advanced gadget', 99.99);
		INSERT INTO comments (user_id, content) VALUES
			(1, 'Welcome to HIVE!'),
			(2, 'This is a test comment'),
			(3, 'Another comment here');
		`
		if _, err := SQLite.Exec(seed); err != nil {
			log.Printf("SQLite seed error: %v", err)
		}
	}
}

func Close() {
	if MySQL != nil {
		MySQL.Close()
	}
	if Postgres != nil {
		Postgres.Close()
	}
	if MSSQL != nil {
		MSSQL.Close()
	}
	if SQLite != nil {
		SQLite.Close()
	}
}
```

**Step 3: Update main.go to use db package**

```go
// main.go
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/subzerodev/hive/db"
)

func main() {
	// Initialize databases
	db.Init()
	defer db.Close()

	// Health endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"healthy"}`))
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		log.Println("Shutting down...")
		db.Close()
		os.Exit(0)
	}()

	log.Printf("HIVE starting on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}
```

**Step 4: Verify it compiles**

```bash
go build -o hive .
```

**Step 5: Commit**

```bash
git add db/ main.go go.mod go.sum
git commit -m "feat: add database connections for all 4 databases"
```

---

### Task 1.7: Add Static File Serving

**Files:**
- Modify: `main.go`

**Step 1: Add static file handler in main.go before ListenAndServe**

```go
// Add after health endpoint, before ListenAndServe
// Static files with directory listing enabled
fs := http.FileServer(http.Dir("./static"))
http.Handle("/static/", http.StripPrefix("/static/", fs))
```

**Step 2: Create test static file**

```bash
mkdir -p static/test
echo "Test file content" > static/test/file.txt
```

**Step 3: Test locally**

```bash
go run . &
curl http://localhost:8080/static/test/file.txt
kill %1
```

Expected: `Test file content`

**Step 4: Commit**

```bash
git add main.go static/test/
git commit -m "feat: add static file serving with directory listing"
```

---

### Task 1.8: Add Reset API Endpoint

**Files:**
- Create: `api/reset.go`
- Modify: `main.go`

**Step 1: Create api package**

```go
// api/reset.go
package api

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/subzerodev/hive/db"
)

func ResetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var errors []string

	// Reset MySQL
	if db.MySQL != nil {
		if err := resetMySQL(); err != nil {
			errors = append(errors, "mysql: "+err.Error())
		}
	}

	// Reset PostgreSQL
	if db.Postgres != nil {
		if err := resetPostgres(); err != nil {
			errors = append(errors, "postgres: "+err.Error())
		}
	}

	// Reset MSSQL
	if db.MSSQL != nil {
		if err := resetMSSQL(); err != nil {
			errors = append(errors, "mssql: "+err.Error())
		}
	}

	// Reset SQLite
	if db.SQLite != nil {
		if err := resetSQLite(); err != nil {
			errors = append(errors, "sqlite: "+err.Error())
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if len(errors) > 0 {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "partial",
			"errors": errors,
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "reset complete"})
}

func resetMySQL() error {
	log.Println("Resetting MySQL...")
	_, err := db.MySQL.Exec("DELETE FROM comments")
	if err != nil {
		return err
	}
	_, err = db.MySQL.Exec("DELETE FROM products")
	if err != nil {
		return err
	}
	_, err = db.MySQL.Exec("DELETE FROM users")
	if err != nil {
		return err
	}

	seed, err := os.Open("seed/mysql.sql")
	if err != nil {
		return err
	}
	defer seed.Close()

	content, _ := io.ReadAll(seed)
	_, err = db.MySQL.Exec(string(content))
	return err
}

func resetPostgres() error {
	log.Println("Resetting PostgreSQL...")
	_, err := db.Postgres.Exec("TRUNCATE comments, products, users RESTART IDENTITY")
	if err != nil {
		return err
	}

	seed, err := os.Open("seed/postgres.sql")
	if err != nil {
		return err
	}
	defer seed.Close()

	content, _ := io.ReadAll(seed)
	_, err = db.Postgres.Exec(string(content))
	return err
}

func resetMSSQL() error {
	log.Println("Resetting MSSQL...")
	_, err := db.MSSQL.Exec("DELETE FROM comments; DELETE FROM products; DELETE FROM users;")
	return err
}

func resetSQLite() error {
	log.Println("Resetting SQLite...")
	_, err := db.SQLite.Exec("DELETE FROM comments; DELETE FROM products; DELETE FROM users;")
	if err != nil {
		return err
	}

	seed := `
	INSERT INTO users (username, password, email, role) VALUES
		('admin', 'password', 'admin@hive.local', 'admin'),
		('user1', 'pass123', 'user1@hive.local', 'user'),
		('user2', 'pass456', 'user2@hive.local', 'user');
	INSERT INTO products (name, description, price) VALUES
		('Widget A', 'A standard widget', 19.99),
		('Widget B', 'A premium widget', 49.99),
		('Gadget X', 'An advanced gadget', 99.99);
	INSERT INTO comments (user_id, content) VALUES
		(1, 'Welcome to HIVE!'),
		(2, 'This is a test comment'),
		(3, 'Another comment here');
	`
	_, err = db.SQLite.Exec(seed)
	return err
}
```

**Step 2: Register handler in main.go**

```go
// Add import
import "github.com/subzerodev/hive/api"

// Add after static file handler
http.HandleFunc("/api/reset", api.ResetHandler)
```

**Step 3: Verify it compiles**

```bash
go build -o hive .
```

**Step 4: Commit**

```bash
git add api/ main.go
git commit -m "feat: add /api/reset endpoint for CI"
```

---

### Task 1.9: Create Root Landing Page

**Files:**
- Create: `vulns/index.html`
- Modify: `main.go`

**Step 1: Create landing page**

```html
<!-- vulns/index.html -->
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>HIVE - Hazardous Intentionally Vulnerable Environment</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
        h1 { color: #c00; }
        ul { list-style: none; padding: 0; }
        li { margin: 8px 0; }
        a { color: #0066cc; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .section { margin: 30px 0; }
    </style>
</head>
<body>
    <h1>HIVE</h1>
    <p><strong>Hazardous Intentionally Vulnerable Environment</strong></p>
    <p>A vulnerability testbed for validating web vulnerability scanners.</p>

    <div class="section">
        <h2>Vulnerability Categories</h2>
        <ul>
            <li><a href="/vulns/injection/">Injection</a> - SQLi, Command, LDAP, XPath, SSI, SSTI, Code, XML</li>
            <li><a href="/vulns/xss/">Cross-Site Scripting</a> - Reflected, DOM, Stored, Framework</li>
            <li><a href="/vulns/file/">File/Path</a> - Traversal, Upload, Source Disclosure</li>
            <li><a href="/vulns/auth-session/">Auth/Session</a> - CSRF, Cookies, Password Exposure</li>
            <li><a href="/vulns/info-disclosure/">Info Disclosure</a> - Errors, PII, Keys, Versions</li>
            <li><a href="/vulns/config/">Configuration</a> - CORS, CSP, Clickjacking, Headers</li>
            <li><a href="/vulns/serialization/">Serialization</a></li>
            <li><a href="/vulns/ssrf/">SSRF</a> - HTTP, DNS</li>
            <li><a href="/vulns/backdoors/">Backdoors</a></li>
        </ul>
    </div>

    <div class="section">
        <h2>Authentication Testing</h2>
        <ul>
            <li><a href="/vulns/auth/">Auth Flows</a> - Form, AJAX, Multi-step, OAuth, HTTP Basic, JWT</li>
        </ul>
    </div>

    <div class="section">
        <h2>Static Files</h2>
        <ul>
            <li><a href="/static/">Directory Listing &amp; File Tests</a></li>
        </ul>
    </div>

    <div class="section">
        <h2>API</h2>
        <ul>
            <li><code>GET /health</code> - Health check</li>
            <li><code>POST /api/reset</code> - Reset all databases</li>
        </ul>
    </div>
</body>
</html>
```

**Step 2: Add vulns file server in main.go**

```go
// Add after static file handler
// Vulnerability test cases
vulnsFs := http.FileServer(http.Dir("./vulns"))
http.Handle("/vulns/", http.StripPrefix("/vulns/", vulnsFs))

// Root redirect to vulns
http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		http.Redirect(w, r, "/vulns/", http.StatusFound)
		return
	}
	http.NotFound(w, r)
})
```

**Step 3: Test locally**

```bash
go run . &
curl http://localhost:8080/
curl http://localhost:8080/vulns/
kill %1
```

Expected: Redirect to /vulns/, then HTML content.

**Step 4: Commit**

```bash
git add vulns/index.html main.go
git commit -m "feat: add root landing page with vulnerability categories"
```

---

## Phase 2: SQL Injection Test Cases

### Task 2.1: Create Injection Category Index

**Files:**
- Create: `vulns/injection/index.html`

**Step 1: Create injection index page**

```html
<!-- vulns/injection/index.html -->
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Injection - HIVE</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
        a { color: #0066cc; }
        .back { margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="back"><a href="/vulns/">&larr; Back to HIVE</a></div>
    <h1>Injection Vulnerabilities</h1>

    <h2>SQL Injection</h2>
    <ul>
        <li><a href="/vulns/injection/sqli/mysql/">MySQL</a></li>
        <li><a href="/vulns/injection/sqli/postgres/">PostgreSQL</a></li>
        <li><a href="/vulns/injection/sqli/mssql/">MSSQL</a></li>
        <li><a href="/vulns/injection/sqli/sqlite/">SQLite</a></li>
    </ul>

    <h2>Command Injection</h2>
    <ul>
        <li><a href="/vulns/injection/command/">Command Injection</a></li>
    </ul>

    <h2>Other Injection</h2>
    <ul>
        <li><a href="/vulns/injection/ldap/">LDAP Injection</a></li>
        <li><a href="/vulns/injection/xpath/">XPath Injection</a></li>
        <li><a href="/vulns/injection/ssi/">SSI Injection</a></li>
        <li><a href="/vulns/injection/ssti/">SSTI</a></li>
        <li><a href="/vulns/injection/code/">Code Injection</a></li>
        <li><a href="/vulns/injection/xml/">XML/XXE</a></li>
        <li><a href="/vulns/injection/expression-language/">Expression Language</a></li>
        <li><a href="/vulns/injection/smtp-header/">SMTP Header</a></li>
    </ul>
</body>
</html>
```

**Step 2: Create directory structure**

```bash
mkdir -p vulns/injection/sqli/{mysql,postgres,mssql,sqlite}
mkdir -p vulns/injection/{command,ldap,xpath,ssi,ssti,code,xml,expression-language,smtp-header}
```

**Step 3: Commit**

```bash
git add vulns/injection/
git commit -m "feat: add injection category index and directory structure"
```

---

### Task 2.2: Create Handler Registration System

**Files:**
- Create: `handlers/handlers.go`
- Modify: `main.go`

**Step 1: Create handlers package for dynamic routes**

```go
// handlers/handlers.go
package handlers

import (
	"net/http"
	"sync"
)

var (
	mux     = http.NewServeMux()
	once    sync.Once
	initFns []func()
)

// Register adds an init function to be called during setup
func Register(fn func()) {
	initFns = append(initFns, fn)
}

// Init calls all registered init functions
func Init() {
	once.Do(func() {
		for _, fn := range initFns {
			fn()
		}
	})
}

// Handle registers a handler for a pattern
func Handle(pattern string, handler http.HandlerFunc) {
	mux.HandleFunc(pattern, handler)
}

// Mux returns the handler mux
func Mux() *http.ServeMux {
	return mux
}
```

**Step 2: Update main.go to use handlers mux**

```go
// main.go - updated
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/subzerodev/hive/api"
	"github.com/subzerodev/hive/db"
	"github.com/subzerodev/hive/handlers"

	// Import vulnerability handlers (they register via init)
	_ "github.com/subzerodev/hive/vulns/injection/sqli/mysql"
)

func main() {
	// Initialize databases
	db.Init()
	defer db.Close()

	// Initialize handlers
	handlers.Init()

	// Health endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"healthy"}`))
	})

	// Reset API
	http.HandleFunc("/api/reset", api.ResetHandler)

	// Static files with directory listing
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Vulnerability test cases - dynamic handlers first
	http.Handle("/vulns/injection/", handlers.Mux())

	// Vulnerability test cases - static HTML files
	vulnsFs := http.FileServer(http.Dir("./vulns"))
	http.Handle("/vulns/", http.StripPrefix("/vulns/", vulnsFs))

	// Root redirect
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/vulns/", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		log.Println("Shutting down...")
		db.Close()
		os.Exit(0)
	}()

	log.Printf("HIVE starting on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}
```

**Step 3: Commit**

```bash
git add handlers/ main.go
git commit -m "feat: add handler registration system for dynamic routes"
```

---

### Task 2.3: Create MySQL SQLi Error-Based Test Case

**Files:**
- Create: `vulns/injection/sqli/mysql/handlers.go`
- Create: `vulns/injection/sqli/mysql/index.html`

**Step 1: Create MySQL SQLi handlers**

```go
// vulns/injection/sqli/mysql/handlers.go
package mysql

import (
	"fmt"
	"net/http"

	"github.com/subzerodev/hive/db"
	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		// Error-based SQLi
		handlers.Handle("/vulns/injection/sqli/mysql/error-based", errorBased)

		// Union-based SQLi
		handlers.Handle("/vulns/injection/sqli/mysql/union-based", unionBased)

		// Blind boolean SQLi
		handlers.Handle("/vulns/injection/sqli/mysql/blind-boolean", blindBoolean)

		// Blind time SQLi
		handlers.Handle("/vulns/injection/sqli/mysql/blind-time", blindTime)

		// False positive - parameterized
		handlers.Handle("/vulns/injection/sqli/mysql/fp/parameterized", fpParameterized)
	})
}

func errorBased(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>MySQL Error-Based SQLi</title></head>
<body>
<h1>User Lookup</h1>
<form method="GET">
    <input name="id" value="%s" placeholder="User ID">
    <button type="submit">Search</button>
</form>
<h2>Results:</h2>
<pre>`, id)

	// VULNERABLE: Direct string concatenation
	query := "SELECT id, username, email FROM users WHERE id = " + id
	rows, err := db.MySQL.Query(query)
	if err != nil {
		// Leak error message (intentional vulnerability)
		fmt.Fprintf(w, "Error: %s", err.Error())
	} else {
		defer rows.Close()
		for rows.Next() {
			var uid int
			var username, email string
			rows.Scan(&uid, &username, &email)
			fmt.Fprintf(w, "ID: %d, Username: %s, Email: %s\n", uid, username, email)
		}
	}

	fmt.Fprintf(w, `</pre></body></html>`)
}

func unionBased(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>MySQL Union-Based SQLi</title></head>
<body>
<h1>Product Lookup</h1>
<form method="GET">
    <input name="id" value="%s" placeholder="Product ID">
    <button type="submit">Search</button>
</form>
<h2>Results:</h2>
<pre>`, id)

	// VULNERABLE: Direct string concatenation, returns multiple columns
	query := "SELECT id, name, description FROM products WHERE id = " + id
	rows, err := db.MySQL.Query(query)
	if err != nil {
		fmt.Fprintf(w, "Error: %s", err.Error())
	} else {
		defer rows.Close()
		for rows.Next() {
			var pid int
			var name, desc string
			rows.Scan(&pid, &name, &desc)
			fmt.Fprintf(w, "ID: %d, Name: %s, Description: %s\n", pid, name, desc)
		}
	}

	fmt.Fprintf(w, `</pre></body></html>`)
}

func blindBoolean(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html")

	// VULNERABLE: Boolean-based blind SQLi
	query := "SELECT username FROM users WHERE id = " + id
	var username string
	err := db.MySQL.QueryRow(query).Scan(&username)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>MySQL Blind Boolean SQLi</title></head>
<body>
<h1>User Exists Check</h1>
<form method="GET">
    <input name="id" value="%s" placeholder="User ID">
    <button type="submit">Check</button>
</form>
<h2>Result:</h2>`, id)

	if err != nil {
		fmt.Fprintf(w, `<p>User not found.</p>`)
	} else {
		fmt.Fprintf(w, `<p>User exists!</p>`)
	}

	fmt.Fprintf(w, `</body></html>`)
}

func blindTime(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html")

	// VULNERABLE: Time-based blind SQLi
	query := "SELECT username FROM users WHERE id = " + id
	var username string
	db.MySQL.QueryRow(query).Scan(&username)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>MySQL Blind Time SQLi</title></head>
<body>
<h1>User Lookup (Time-based)</h1>
<form method="GET">
    <input name="id" value="%s" placeholder="User ID">
    <button type="submit">Search</button>
</form>
<h2>Result:</h2>
<p>Query completed.</p>
<p><small>Try: 1 AND SLEEP(5)</small></p>
</body></html>`, id)
}

func fpParameterized(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>MySQL Parameterized (Safe)</title></head>
<body>
<h1>User Lookup (Safe)</h1>
<form method="GET">
    <input name="id" value="%s" placeholder="User ID">
    <button type="submit">Search</button>
</form>
<h2>Results:</h2>
<pre>`, id)

	// SAFE: Parameterized query
	rows, err := db.MySQL.Query("SELECT id, username, email FROM users WHERE id = ?", id)
	if err != nil {
		fmt.Fprintf(w, "Error: query failed")
	} else {
		defer rows.Close()
		for rows.Next() {
			var uid int
			var username, email string
			rows.Scan(&uid, &username, &email)
			fmt.Fprintf(w, "ID: %d, Username: %s, Email: %s\n", uid, username, email)
		}
	}

	fmt.Fprintf(w, `</pre></body></html>`)
}
```

**Step 2: Create MySQL SQLi index page**

```html
<!-- vulns/injection/sqli/mysql/index.html -->
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>MySQL SQLi - HIVE</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
        a { color: #0066cc; }
        .back { margin-bottom: 20px; }
        .vuln { color: #c00; }
        .safe { color: #080; }
    </style>
</head>
<body>
    <div class="back"><a href="/vulns/injection/">&larr; Back to Injection</a></div>
    <h1>MySQL SQL Injection</h1>

    <h2 class="vuln">Vulnerable Test Cases</h2>
    <ul>
        <li><a href="/vulns/injection/sqli/mysql/error-based?id=1">Error-Based</a> - Error messages reveal data</li>
        <li><a href="/vulns/injection/sqli/mysql/union-based?id=1">Union-Based</a> - UNION SELECT to extract data</li>
        <li><a href="/vulns/injection/sqli/mysql/blind-boolean?id=1">Blind Boolean</a> - True/false responses</li>
        <li><a href="/vulns/injection/sqli/mysql/blind-time?id=1">Blind Time</a> - Time delays via SLEEP()</li>
    </ul>

    <h2 class="safe">False Positives (Safe)</h2>
    <ul>
        <li><a href="/vulns/injection/sqli/mysql/fp/parameterized?id=1">Parameterized Query</a> - Uses prepared statements</li>
    </ul>
</body>
</html>
```

**Step 3: Verify it compiles**

```bash
go build -o hive .
```

**Step 4: Commit**

```bash
git add vulns/injection/sqli/mysql/
git commit -m "feat: add MySQL SQLi test cases (error, union, blind, fp)"
```

---

### Task 2.4: Create PostgreSQL SQLi Test Cases

**Files:**
- Create: `vulns/injection/sqli/postgres/handlers.go`
- Create: `vulns/injection/sqli/postgres/index.html`

**Step 1: Create PostgreSQL SQLi handlers**

```go
// vulns/injection/sqli/postgres/handlers.go
package postgres

import (
	"fmt"
	"net/http"

	"github.com/subzerodev/hive/db"
	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/injection/sqli/postgres/error-based", errorBased)
		handlers.Handle("/vulns/injection/sqli/postgres/union-based", unionBased)
		handlers.Handle("/vulns/injection/sqli/postgres/blind-boolean", blindBoolean)
		handlers.Handle("/vulns/injection/sqli/postgres/blind-time", blindTime)
		handlers.Handle("/vulns/injection/sqli/postgres/fp/parameterized", fpParameterized)
	})
}

func errorBased(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>PostgreSQL Error-Based SQLi</title></head>
<body>
<h1>User Lookup</h1>
<form method="GET">
    <input name="id" value="%s" placeholder="User ID">
    <button type="submit">Search</button>
</form>
<h2>Results:</h2>
<pre>`, id)

	// VULNERABLE: Direct string concatenation
	query := "SELECT id, username, email FROM users WHERE id = " + id
	rows, err := db.Postgres.Query(query)
	if err != nil {
		// PostgreSQL error messages
		fmt.Fprintf(w, "Error: %s", err.Error())
	} else {
		defer rows.Close()
		for rows.Next() {
			var uid int
			var username, email string
			rows.Scan(&uid, &username, &email)
			fmt.Fprintf(w, "ID: %d, Username: %s, Email: %s\n", uid, username, email)
		}
	}

	fmt.Fprintf(w, `</pre></body></html>`)
}

func unionBased(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>PostgreSQL Union-Based SQLi</title></head>
<body>
<h1>Product Lookup</h1>
<form method="GET">
    <input name="id" value="%s" placeholder="Product ID">
    <button type="submit">Search</button>
</form>
<h2>Results:</h2>
<pre>`, id)

	query := "SELECT id, name, description FROM products WHERE id = " + id
	rows, err := db.Postgres.Query(query)
	if err != nil {
		fmt.Fprintf(w, "Error: %s", err.Error())
	} else {
		defer rows.Close()
		for rows.Next() {
			var pid int
			var name, desc string
			rows.Scan(&pid, &name, &desc)
			fmt.Fprintf(w, "ID: %d, Name: %s, Description: %s\n", pid, name, desc)
		}
	}

	fmt.Fprintf(w, `</pre></body></html>`)
}

func blindBoolean(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html")

	query := "SELECT username FROM users WHERE id = " + id
	var username string
	err := db.Postgres.QueryRow(query).Scan(&username)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>PostgreSQL Blind Boolean SQLi</title></head>
<body>
<h1>User Exists Check</h1>
<form method="GET">
    <input name="id" value="%s" placeholder="User ID">
    <button type="submit">Check</button>
</form>
<h2>Result:</h2>`, id)

	if err != nil {
		fmt.Fprintf(w, `<p>User not found.</p>`)
	} else {
		fmt.Fprintf(w, `<p>User exists!</p>`)
	}

	fmt.Fprintf(w, `</body></html>`)
}

func blindTime(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html")

	// VULNERABLE: Time-based blind SQLi (PostgreSQL uses pg_sleep)
	query := "SELECT username FROM users WHERE id = " + id
	var username string
	db.Postgres.QueryRow(query).Scan(&username)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>PostgreSQL Blind Time SQLi</title></head>
<body>
<h1>User Lookup (Time-based)</h1>
<form method="GET">
    <input name="id" value="%s" placeholder="User ID">
    <button type="submit">Search</button>
</form>
<h2>Result:</h2>
<p>Query completed.</p>
<p><small>Try: 1; SELECT pg_sleep(5)--</small></p>
</body></html>`, id)
}

func fpParameterized(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>PostgreSQL Parameterized (Safe)</title></head>
<body>
<h1>User Lookup (Safe)</h1>
<form method="GET">
    <input name="id" value="%s" placeholder="User ID">
    <button type="submit">Search</button>
</form>
<h2>Results:</h2>
<pre>`, id)

	// SAFE: Parameterized query (PostgreSQL uses $1, $2, etc.)
	rows, err := db.Postgres.Query("SELECT id, username, email FROM users WHERE id = $1", id)
	if err != nil {
		fmt.Fprintf(w, "Error: query failed")
	} else {
		defer rows.Close()
		for rows.Next() {
			var uid int
			var username, email string
			rows.Scan(&uid, &username, &email)
			fmt.Fprintf(w, "ID: %d, Username: %s, Email: %s\n", uid, username, email)
		}
	}

	fmt.Fprintf(w, `</pre></body></html>`)
}
```

**Step 2: Create index page**

```html
<!-- vulns/injection/sqli/postgres/index.html -->
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>PostgreSQL SQLi - HIVE</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
        a { color: #0066cc; }
        .back { margin-bottom: 20px; }
        .vuln { color: #c00; }
        .safe { color: #080; }
    </style>
</head>
<body>
    <div class="back"><a href="/vulns/injection/">&larr; Back to Injection</a></div>
    <h1>PostgreSQL SQL Injection</h1>

    <h2 class="vuln">Vulnerable Test Cases</h2>
    <ul>
        <li><a href="/vulns/injection/sqli/postgres/error-based?id=1">Error-Based</a> - Error messages reveal data</li>
        <li><a href="/vulns/injection/sqli/postgres/union-based?id=1">Union-Based</a> - UNION SELECT to extract data</li>
        <li><a href="/vulns/injection/sqli/postgres/blind-boolean?id=1">Blind Boolean</a> - True/false responses</li>
        <li><a href="/vulns/injection/sqli/postgres/blind-time?id=1">Blind Time</a> - Time delays via pg_sleep()</li>
    </ul>

    <h2 class="safe">False Positives (Safe)</h2>
    <ul>
        <li><a href="/vulns/injection/sqli/postgres/fp/parameterized?id=1">Parameterized Query</a> - Uses prepared statements</li>
    </ul>
</body>
</html>
```

**Step 3: Add import to main.go**

```go
// Add to imports in main.go
_ "github.com/subzerodev/hive/vulns/injection/sqli/postgres"
```

**Step 4: Commit**

```bash
git add vulns/injection/sqli/postgres/ main.go
git commit -m "feat: add PostgreSQL SQLi test cases"
```

---

### Task 2.5: Create MSSQL SQLi Test Cases

**Files:**
- Create: `vulns/injection/sqli/mssql/handlers.go`
- Create: `vulns/injection/sqli/mssql/index.html`

**Step 1: Create MSSQL SQLi handlers**

```go
// vulns/injection/sqli/mssql/handlers.go
package mssql

import (
	"fmt"
	"net/http"

	"github.com/subzerodev/hive/db"
	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/injection/sqli/mssql/error-based", errorBased)
		handlers.Handle("/vulns/injection/sqli/mssql/union-based", unionBased)
		handlers.Handle("/vulns/injection/sqli/mssql/blind-boolean", blindBoolean)
		handlers.Handle("/vulns/injection/sqli/mssql/blind-time", blindTime)
		handlers.Handle("/vulns/injection/sqli/mssql/fp/parameterized", fpParameterized)
	})
}

func errorBased(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>MSSQL Error-Based SQLi</title></head>
<body>
<h1>User Lookup</h1>
<form method="GET">
    <input name="id" value="%s" placeholder="User ID">
    <button type="submit">Search</button>
</form>
<h2>Results:</h2>
<pre>`, id)

	// VULNERABLE: Direct string concatenation
	query := "SELECT id, username, email FROM users WHERE id = " + id
	rows, err := db.MSSQL.Query(query)
	if err != nil {
		// MSSQL error messages
		fmt.Fprintf(w, "Error: %s", err.Error())
	} else {
		defer rows.Close()
		for rows.Next() {
			var uid int
			var username, email string
			rows.Scan(&uid, &username, &email)
			fmt.Fprintf(w, "ID: %d, Username: %s, Email: %s\n", uid, username, email)
		}
	}

	fmt.Fprintf(w, `</pre></body></html>`)
}

func unionBased(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>MSSQL Union-Based SQLi</title></head>
<body>
<h1>Product Lookup</h1>
<form method="GET">
    <input name="id" value="%s" placeholder="Product ID">
    <button type="submit">Search</button>
</form>
<h2>Results:</h2>
<pre>`, id)

	query := "SELECT id, name, description FROM products WHERE id = " + id
	rows, err := db.MSSQL.Query(query)
	if err != nil {
		fmt.Fprintf(w, "Error: %s", err.Error())
	} else {
		defer rows.Close()
		for rows.Next() {
			var pid int
			var name, desc string
			rows.Scan(&pid, &name, &desc)
			fmt.Fprintf(w, "ID: %d, Name: %s, Description: %s\n", pid, name, desc)
		}
	}

	fmt.Fprintf(w, `</pre></body></html>`)
}

func blindBoolean(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html")

	query := "SELECT username FROM users WHERE id = " + id
	var username string
	err := db.MSSQL.QueryRow(query).Scan(&username)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>MSSQL Blind Boolean SQLi</title></head>
<body>
<h1>User Exists Check</h1>
<form method="GET">
    <input name="id" value="%s" placeholder="User ID">
    <button type="submit">Check</button>
</form>
<h2>Result:</h2>`, id)

	if err != nil {
		fmt.Fprintf(w, `<p>User not found.</p>`)
	} else {
		fmt.Fprintf(w, `<p>User exists!</p>`)
	}

	fmt.Fprintf(w, `</body></html>`)
}

func blindTime(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html")

	// VULNERABLE: Time-based blind SQLi (MSSQL uses WAITFOR DELAY)
	query := "SELECT username FROM users WHERE id = " + id
	var username string
	db.MSSQL.QueryRow(query).Scan(&username)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>MSSQL Blind Time SQLi</title></head>
<body>
<h1>User Lookup (Time-based)</h1>
<form method="GET">
    <input name="id" value="%s" placeholder="User ID">
    <button type="submit">Search</button>
</form>
<h2>Result:</h2>
<p>Query completed.</p>
<p><small>Try: 1; WAITFOR DELAY '0:0:5'--</small></p>
</body></html>`, id)
}

func fpParameterized(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>MSSQL Parameterized (Safe)</title></head>
<body>
<h1>User Lookup (Safe)</h1>
<form method="GET">
    <input name="id" value="%s" placeholder="User ID">
    <button type="submit">Search</button>
</form>
<h2>Results:</h2>
<pre>`, id)

	// SAFE: Parameterized query (MSSQL uses @p1, @p2, etc.)
	rows, err := db.MSSQL.Query("SELECT id, username, email FROM users WHERE id = @p1", id)
	if err != nil {
		fmt.Fprintf(w, "Error: query failed")
	} else {
		defer rows.Close()
		for rows.Next() {
			var uid int
			var username, email string
			rows.Scan(&uid, &username, &email)
			fmt.Fprintf(w, "ID: %d, Username: %s, Email: %s\n", uid, username, email)
		}
	}

	fmt.Fprintf(w, `</pre></body></html>`)
}
```

**Step 2: Create index page**

```html
<!-- vulns/injection/sqli/mssql/index.html -->
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>MSSQL SQLi - HIVE</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
        a { color: #0066cc; }
        .back { margin-bottom: 20px; }
        .vuln { color: #c00; }
        .safe { color: #080; }
    </style>
</head>
<body>
    <div class="back"><a href="/vulns/injection/">&larr; Back to Injection</a></div>
    <h1>MSSQL SQL Injection</h1>

    <h2 class="vuln">Vulnerable Test Cases</h2>
    <ul>
        <li><a href="/vulns/injection/sqli/mssql/error-based?id=1">Error-Based</a> - Error messages reveal data</li>
        <li><a href="/vulns/injection/sqli/mssql/union-based?id=1">Union-Based</a> - UNION SELECT to extract data</li>
        <li><a href="/vulns/injection/sqli/mssql/blind-boolean?id=1">Blind Boolean</a> - True/false responses</li>
        <li><a href="/vulns/injection/sqli/mssql/blind-time?id=1">Blind Time</a> - WAITFOR DELAY</li>
    </ul>

    <h2 class="safe">False Positives (Safe)</h2>
    <ul>
        <li><a href="/vulns/injection/sqli/mssql/fp/parameterized?id=1">Parameterized Query</a> - Uses prepared statements</li>
    </ul>
</body>
</html>
```

**Step 3: Add import to main.go**

```go
_ "github.com/subzerodev/hive/vulns/injection/sqli/mssql"
```

**Step 4: Commit**

```bash
git add vulns/injection/sqli/mssql/ main.go
git commit -m "feat: add MSSQL SQLi test cases"
```

---

### Task 2.6: Create SQLite SQLi Test Cases

**Files:**
- Create: `vulns/injection/sqli/sqlite/handlers.go`
- Create: `vulns/injection/sqli/sqlite/index.html`

**Step 1: Create SQLite SQLi handlers**

```go
// vulns/injection/sqli/sqlite/handlers.go
package sqlite

import (
	"fmt"
	"net/http"

	"github.com/subzerodev/hive/db"
	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/injection/sqli/sqlite/error-based", errorBased)
		handlers.Handle("/vulns/injection/sqli/sqlite/union-based", unionBased)
		handlers.Handle("/vulns/injection/sqli/sqlite/blind-boolean", blindBoolean)
		handlers.Handle("/vulns/injection/sqli/sqlite/fp/parameterized", fpParameterized)
	})
}

func errorBased(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SQLite Error-Based SQLi</title></head>
<body>
<h1>User Lookup</h1>
<form method="GET">
    <input name="id" value="%s" placeholder="User ID">
    <button type="submit">Search</button>
</form>
<h2>Results:</h2>
<pre>`, id)

	// VULNERABLE: Direct string concatenation
	query := "SELECT id, username, email FROM users WHERE id = " + id
	rows, err := db.SQLite.Query(query)
	if err != nil {
		// SQLite error messages
		fmt.Fprintf(w, "Error: %s", err.Error())
	} else {
		defer rows.Close()
		for rows.Next() {
			var uid int
			var username, email string
			rows.Scan(&uid, &username, &email)
			fmt.Fprintf(w, "ID: %d, Username: %s, Email: %s\n", uid, username, email)
		}
	}

	fmt.Fprintf(w, `</pre></body></html>`)
}

func unionBased(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SQLite Union-Based SQLi</title></head>
<body>
<h1>Product Lookup</h1>
<form method="GET">
    <input name="id" value="%s" placeholder="Product ID">
    <button type="submit">Search</button>
</form>
<h2>Results:</h2>
<pre>`, id)

	query := "SELECT id, name, description FROM products WHERE id = " + id
	rows, err := db.SQLite.Query(query)
	if err != nil {
		fmt.Fprintf(w, "Error: %s", err.Error())
	} else {
		defer rows.Close()
		for rows.Next() {
			var pid int
			var name, desc string
			rows.Scan(&pid, &name, &desc)
			fmt.Fprintf(w, "ID: %d, Name: %s, Description: %s\n", pid, name, desc)
		}
	}

	fmt.Fprintf(w, `</pre></body></html>`)
}

func blindBoolean(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html")

	query := "SELECT username FROM users WHERE id = " + id
	var username string
	err := db.SQLite.QueryRow(query).Scan(&username)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SQLite Blind Boolean SQLi</title></head>
<body>
<h1>User Exists Check</h1>
<form method="GET">
    <input name="id" value="%s" placeholder="User ID">
    <button type="submit">Check</button>
</form>
<h2>Result:</h2>`, id)

	if err != nil {
		fmt.Fprintf(w, `<p>User not found.</p>`)
	} else {
		fmt.Fprintf(w, `<p>User exists!</p>`)
	}

	fmt.Fprintf(w, `</body></html>`)
}

func fpParameterized(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "1"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SQLite Parameterized (Safe)</title></head>
<body>
<h1>User Lookup (Safe)</h1>
<form method="GET">
    <input name="id" value="%s" placeholder="User ID">
    <button type="submit">Search</button>
</form>
<h2>Results:</h2>
<pre>`, id)

	// SAFE: Parameterized query
	rows, err := db.SQLite.Query("SELECT id, username, email FROM users WHERE id = ?", id)
	if err != nil {
		fmt.Fprintf(w, "Error: query failed")
	} else {
		defer rows.Close()
		for rows.Next() {
			var uid int
			var username, email string
			rows.Scan(&uid, &username, &email)
			fmt.Fprintf(w, "ID: %d, Username: %s, Email: %s\n", uid, username, email)
		}
	}

	fmt.Fprintf(w, `</pre></body></html>`)
}
```

**Step 2: Create index page**

```html
<!-- vulns/injection/sqli/sqlite/index.html -->
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SQLite SQLi - HIVE</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
        a { color: #0066cc; }
        .back { margin-bottom: 20px; }
        .vuln { color: #c00; }
        .safe { color: #080; }
    </style>
</head>
<body>
    <div class="back"><a href="/vulns/injection/">&larr; Back to Injection</a></div>
    <h1>SQLite SQL Injection</h1>

    <h2 class="vuln">Vulnerable Test Cases</h2>
    <ul>
        <li><a href="/vulns/injection/sqli/sqlite/error-based?id=1">Error-Based</a> - Error messages reveal data</li>
        <li><a href="/vulns/injection/sqli/sqlite/union-based?id=1">Union-Based</a> - UNION SELECT to extract data</li>
        <li><a href="/vulns/injection/sqli/sqlite/blind-boolean?id=1">Blind Boolean</a> - True/false responses</li>
    </ul>
    <p><em>Note: SQLite does not support time-based delays like SLEEP().</em></p>

    <h2 class="safe">False Positives (Safe)</h2>
    <ul>
        <li><a href="/vulns/injection/sqli/sqlite/fp/parameterized?id=1">Parameterized Query</a> - Uses prepared statements</li>
    </ul>
</body>
</html>
```

**Step 3: Add import to main.go**

```go
_ "github.com/subzerodev/hive/vulns/injection/sqli/sqlite"
```

**Step 4: Commit**

```bash
git add vulns/injection/sqli/sqlite/ main.go
git commit -m "feat: add SQLite SQLi test cases"
```

---

### Task 2.7: Create SQLi Category Index

**Files:**
- Create: `vulns/injection/sqli/index.html`

**Step 1: Create SQLi index page**

```html
<!-- vulns/injection/sqli/index.html -->
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SQL Injection - HIVE</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
        a { color: #0066cc; }
        .back { margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="back"><a href="/vulns/injection/">&larr; Back to Injection</a></div>
    <h1>SQL Injection Test Cases</h1>

    <p>Each database has its own set of test cases with database-specific error messages and syntax.</p>

    <h2>By Database</h2>
    <ul>
        <li><a href="/vulns/injection/sqli/mysql/">MySQL</a> - SLEEP(), MySQL error syntax</li>
        <li><a href="/vulns/injection/sqli/postgres/">PostgreSQL</a> - pg_sleep(), PG error syntax</li>
        <li><a href="/vulns/injection/sqli/mssql/">MSSQL</a> - WAITFOR DELAY, SQL Server errors</li>
        <li><a href="/vulns/injection/sqli/sqlite/">SQLite</a> - SQLite error syntax</li>
    </ul>

    <h2>Test Case Types</h2>
    <ul>
        <li><strong>Error-Based</strong> - Error messages leak database information</li>
        <li><strong>Union-Based</strong> - UNION SELECT extracts data from other tables</li>
        <li><strong>Blind Boolean</strong> - Application behavior differs based on true/false conditions</li>
        <li><strong>Blind Time</strong> - Time delays indicate successful injection</li>
        <li><strong>FP Parameterized</strong> - Safe implementation using prepared statements</li>
    </ul>
</body>
</html>
```

**Step 2: Commit**

```bash
git add vulns/injection/sqli/index.html
git commit -m "feat: add SQLi category index page"
```

---

## Phase 3: Command Injection Test Cases

### Task 3.1: Create Command Injection Handlers

**Files:**
- Create: `vulns/injection/command/handlers.go`
- Create: `vulns/injection/command/index.html`

**Step 1: Create command injection handlers**

```go
// vulns/injection/command/handlers.go
package command

import (
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"strings"

	"github.com/subzerodev/hive/handlers"
)

func init() {
	handlers.Register(func() {
		handlers.Handle("/vulns/injection/command/basic", basic)
		handlers.Handle("/vulns/injection/command/blind", blind)
		handlers.Handle("/vulns/injection/command/fp/sanitized", fpSanitized)
	})
}

func basic(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		host = "localhost"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Command Injection - Basic</title></head>
<body>
<h1>Ping Test</h1>
<form method="GET">
    <input name="host" value="%s" placeholder="Hostname">
    <button type="submit">Ping</button>
</form>
<h2>Results:</h2>
<pre>`, host)

	// VULNERABLE: Direct command injection
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", "ping -n 1 "+host)
	} else {
		cmd = exec.Command("sh", "-c", "ping -c 1 "+host)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(w, "Error: %s\n%s", err.Error(), string(output))
	} else {
		fmt.Fprintf(w, "%s", string(output))
	}

	fmt.Fprintf(w, `</pre>
<p><small>Try: localhost; id</small></p>
</body></html>`)
}

func blind(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		host = "localhost"
	}

	w.Header().Set("Content-Type", "text/html")

	// VULNERABLE: Blind command injection (no output)
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", "ping -n 1 "+host)
	} else {
		cmd = exec.Command("sh", "-c", "ping -c 1 "+host)
	}
	cmd.Run() // Output not shown

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Command Injection - Blind</title></head>
<body>
<h1>Ping Test (Blind)</h1>
<form method="GET">
    <input name="host" value="%s" placeholder="Hostname">
    <button type="submit">Ping</button>
</form>
<h2>Result:</h2>
<p>Ping command executed.</p>
<p><small>Try: localhost; sleep 5</small></p>
</body></html>`, host)
}

func fpSanitized(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		host = "localhost"
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Command Injection - Safe</title></head>
<body>
<h1>Ping Test (Safe)</h1>
<form method="GET">
    <input name="host" value="%s" placeholder="Hostname">
    <button type="submit">Ping</button>
</form>
<h2>Results:</h2>
<pre>`, host)

	// SAFE: Sanitized - only allow alphanumeric, dots, and hyphens
	sanitized := sanitizeHost(host)
	if sanitized != host {
		fmt.Fprintf(w, "Invalid hostname characters removed.\n\n")
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", sanitized)
	} else {
		cmd = exec.Command("ping", "-c", "1", sanitized)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(w, "Error: ping failed\n%s", string(output))
	} else {
		fmt.Fprintf(w, "%s", string(output))
	}

	fmt.Fprintf(w, `</pre></body></html>`)
}

func sanitizeHost(host string) string {
	var result strings.Builder
	for _, c := range host {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-' {
			result.WriteRune(c)
		}
	}
	return result.String()
}
```

**Step 2: Create index page**

```html
<!-- vulns/injection/command/index.html -->
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Command Injection - HIVE</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
        a { color: #0066cc; }
        .back { margin-bottom: 20px; }
        .vuln { color: #c00; }
        .safe { color: #080; }
    </style>
</head>
<body>
    <div class="back"><a href="/vulns/injection/">&larr; Back to Injection</a></div>
    <h1>OS Command Injection</h1>

    <h2 class="vuln">Vulnerable Test Cases</h2>
    <ul>
        <li><a href="/vulns/injection/command/basic?host=localhost">Basic</a> - Output shown, try: localhost; id</li>
        <li><a href="/vulns/injection/command/blind?host=localhost">Blind</a> - No output, try: localhost; sleep 5</li>
    </ul>

    <h2 class="safe">False Positives (Safe)</h2>
    <ul>
        <li><a href="/vulns/injection/command/fp/sanitized?host=localhost">Sanitized</a> - Input filtered to alphanumeric only</li>
    </ul>
</body>
</html>
```

**Step 3: Add import to main.go**

```go
_ "github.com/subzerodev/hive/vulns/injection/command"
```

**Step 4: Commit**

```bash
git add vulns/injection/command/ main.go
git commit -m "feat: add command injection test cases"
```

---

## Continuing Implementation

The plan continues with similar patterns for remaining vulnerability categories. Each follows the same structure:

1. Create handlers.go with vulnerable and FP endpoints
2. Create index.html linking to test cases
3. Add import to main.go
4. Commit

### Remaining Phases (summarized):

**Phase 4: XSS Test Cases**
- Task 4.1: Reflected XSS - HTML body context
- Task 4.2: Reflected XSS - Attribute contexts
- Task 4.3: Reflected XSS - JavaScript contexts
- Task 4.4: DOM-based XSS - innerHTML, document.write
- Task 4.5: Stored XSS - Comments, profiles
- Task 4.6: Framework XSS - Angular, React, Vue

**Phase 5: File/Path Vulnerabilities**
- Task 5.1: Path traversal (GET, POST, headers)
- Task 5.2: File upload
- Task 5.3: Static files (backup, configs, keys)

**Phase 6: Auth/Session**
- Task 6.1: CSRF
- Task 6.2: Cookie flags
- Task 6.3: Session in URL
- Task 6.4: Auth bypass

**Phase 7: Info Disclosure**
- Task 7.1: Database error messages
- Task 7.2: PII disclosure
- Task 7.3: Version disclosure

**Phase 8: Configuration**
- Task 8.1: CORS
- Task 8.2: CSP
- Task 8.3: Clickjacking
- Task 8.4: HTTP methods
- Task 8.5: Host header
- Task 8.6: Open redirect

**Phase 9: Authentication Flows**
- Task 9.1: Form POST auth
- Task 9.2: AJAX JSON auth
- Task 9.3: Multi-step auth
- Task 9.4: OAuth flow
- Task 9.5: HTTP Basic
- Task 9.6: JWT auth

**Phase 10: Remaining**
- Task 10.1: SSRF
- Task 10.2: Serialization
- Task 10.3: Backdoors (static files)

---

## Final Tasks

### Task F.1: Update Dockerfile for All Handlers

Update Dockerfile to ensure all handler packages are compiled in.

### Task F.2: Test Full Docker Compose Stack

```bash
docker-compose up --build
curl http://localhost:8080/health
curl http://localhost:8080/vulns/
```

### Task F.3: Push to Remote

```bash
git push origin main
```
