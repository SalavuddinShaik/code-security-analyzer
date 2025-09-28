// Test SQL injection detection
const userId = req.params.id;
const query = "SELECT * FROM users WHERE id = " + userId;
const insertQuery = "INSERT INTO users (name) VALUES ('" + userName + "')";
const updateQuery = "UPDATE users SET email = 'test'" + userEmail;
db.query("SELECT * FROM posts WHERE author = " + authorId);
const templateQuery = `SELECT * FROM users WHERE id = ${userId}`;

// Test hardcoded secrets too
const apiKey = "test";
const password = "mySecretPassword123";
