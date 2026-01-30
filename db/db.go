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
