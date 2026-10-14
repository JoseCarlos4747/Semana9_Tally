// ver-db.js
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('database.sqlite');

console.log('\n========== USUARIOS ==========');
db.all("SELECT id, email, password FROM Users", (err, rows) => {
  if (err) console.error('Error:', err.message);
  else console.table(rows);

  console.log('\n========== TAREAS ==========');
  db.all("SELECT id, userId, title, description FROM Tasks", (err, rows) => {
    if (err) console.error('Error:', err.message);
    else console.table(rows);
    
    console.log('\n========== VERIFICACIÓN BCRYPT ==========');
    db.all("SELECT email, substr(password, 1, 30) || '...' AS hash_parcial FROM Users", (err, rows) => {
      if (err) console.error('Error:', err.message);
      else console.table(rows);
      
      db.close();
    });
  });
});