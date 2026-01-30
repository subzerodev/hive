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
