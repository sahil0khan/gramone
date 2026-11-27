# GramOne

## PostgreSQL accounts and Java authentication

GramOne stores account names, usernames, email addresses, password salts, and password hashes in PostgreSQL. Passwords are hashed in Java with PBKDF2-HMAC-SHA-256; plaintext passwords are not stored. The `gramone_accounts` table is created automatically when the server starts.

Create a PostgreSQL role and database (replace the example password with a private value):

```sql
CREATE ROLE gramone LOGIN PASSWORD 'replace-with-a-private-password';
CREATE DATABASE gramone OWNER gramone;
```

In PowerShell, configure the database connection and start the Java server:

```powershell
$env:GRAMONE_DB_URL = "jdbc:postgresql://localhost:5432/gramone"
$env:GRAMONE_DB_USER = "gramone"
$env:GRAMONE_DB_PASSWORD = "your-private-database-password"
mvn compile exec:java
```

`GRAMONE_DB_URL` defaults to `jdbc:postgresql://localhost:5432/gramone` and `GRAMONE_DB_USER` defaults to `gramone`. `GRAMONE_DB_PASSWORD` must be set. Do not commit database credentials.

Account creation is available from the sign-in page. Users may sign in with their username or email address. New passwords must be 10–128 characters; usernames must be 3–32 letters, numbers, dots, underscores, or hyphens.

## Temporary demo account

Until PostgreSQL is configured, sign in with username `demo` and password `gramone123`. This temporary demo login is for local preview only; it is not a database account and should be removed before deployment.
