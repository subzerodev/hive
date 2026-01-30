// api/reset.go
package api

import (
	"encoding/json"
	"log"
	"net/http"

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
	_, err := db.MySQL.Exec("DELETE FROM comments; DELETE FROM products; DELETE FROM users;")
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
	_, err = db.MySQL.Exec(seed)
	return err
}

func resetPostgres() error {
	log.Println("Resetting PostgreSQL...")
	_, err := db.Postgres.Exec("TRUNCATE comments, products, users RESTART IDENTITY")
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
	_, err = db.Postgres.Exec(seed)
	return err
}

func resetMSSQL() error {
	log.Println("Resetting MSSQL...")
	_, err := db.MSSQL.Exec("DELETE FROM comments; DELETE FROM products; DELETE FROM users;")
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
	_, err = db.MSSQL.Exec(seed)
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
