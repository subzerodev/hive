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
