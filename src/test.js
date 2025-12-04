// COMPLETE TEST FILE - ALL 32 PATTERNS

// 1. HARDCODED SECRETS (4 patterns)
const apiKey = "sk-1234567890abcdefghijklmnop";
const password = "mySecretPassword123";
// password=""
const secret = "super-secret-key-abc123def456ghi";
const token =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N";

// 2. SQL INJECTION (6 patterns)
const query1 = "SELECT * FROM users WHERE id = " + userId;
const query2 = "INSERT INTO users (name) VALUES ('" + userName + "')";
const query3 = "UPDATE users SET email = 'test'" + userEmail;
const query4 = "DELETE FROM users WHERE id = " + id;
db.query("SELECT * FROM posts WHERE author = " + visitorId);
const query5 = `SELECT * FROM users WHERE id = ${visitorId}`;
// 3. XSS (5 patterns)
element.innerHTML = userInput;
document.write(userContent);
$("#div").html(userData);
element.outerHTML = htmlContent;
eval(userCode);

// 4. INSECURE PATTERNS (4 patterns)
console.log("Password is:", password);
localStorage.setItem("authToken", token);
fetch("https://api.com?password=secret123");
const sessionId = Math.random() * 1000 + visitorId;

// 5. WEAK RANDOM (2 patterns)
const randomNum = Math.random() * 999999;
const id = Math.floor(Math.random() * 100);

// 6. WEAK CRYPTO - Week 11 (3 patterns)
const crypto = require("crypto");
const hash1 = crypto.createHash("md5");
const hash2 = crypto.createHash("sha1");
const cipher = crypto.createCipher("des", "key");
const encryptionKey = "my-hardcoded-encryption-key";

// 7. INSECURE HTTP - Week 11 (2 patterns)
fetch("http://api.example.com/data");
const apiUrl = "http://insecure-api.com/endpoint";

// 8. DEBUG MODE - Week 11 (2 patterns)
const DEBUG = true;
console.debug("Debug info:", data);

// 9. COMMAND INJECTION - Week 11 (2 patterns)
const { exec } = require("child_process");
exec("ls " + userInput);
exec(`cat ${filename}`);

// 10. PATH TRAVERSAL - Week 11 (2 patterns)
const fs = require("fs");
fs.readFile("./uploads/" + filename);
const badPath = "../../../etc/passwd";
