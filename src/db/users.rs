//! User management database operations.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rusqlite::{params, Connection};

use crate::crypto::generate_user_salt;
use crate::Result;

/// User record from the database
#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub email: Option<String>,
    pub password_hash: String,
    pub encryption_salt: Vec<u8>,
    pub callsign: Option<String>,
    pub is_admin: bool,
    pub is_active: bool,
    pub theme: String,
    pub created_at: String,
    pub updated_at: String,
    pub last_login_at: Option<String>,
}

/// Parameters for creating a new user
#[derive(Debug)]
pub struct CreateUser {
    pub username: String,
    pub password: String,
    pub email: Option<String>,
    pub callsign: Option<String>,
    pub is_admin: bool,
}

/// Hash a password using Argon2id
pub fn hash_password(password: &str) -> std::result::Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    Ok(argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

/// Verify a password against a hash
pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

/// Create a new user
pub fn create_user(conn: &Connection, user: CreateUser) -> Result<User> {
    let password_hash =
        hash_password(&user.password).map_err(|e| crate::Error::Other(e.to_string()))?;
    let encryption_salt = generate_user_salt();

    conn.execute(
        r#"
        INSERT INTO users (username, email, password_hash, encryption_salt, callsign, is_admin)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        "#,
        params![
            &user.username,
            &user.email,
            &password_hash,
            encryption_salt.as_slice(),
            &user.callsign,
            user.is_admin,
        ],
    )?;

    let id = conn.last_insert_rowid();

    // Fetch the created user
    get_user_by_id(conn, id)?
        .ok_or_else(|| crate::Error::Other("Failed to fetch created user".into()))
}

/// Get user by username
pub fn get_user_by_username(conn: &Connection, username: &str) -> Result<Option<User>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT id, username, email, password_hash, encryption_salt, callsign,
               is_admin, is_active, theme, created_at, updated_at, last_login_at
        FROM users WHERE username = ?1
        "#,
    )?;

    let user = stmt
        .query_row([username], |row| {
            Ok(User {
                id: row.get(0)?,
                username: row.get(1)?,
                email: row.get(2)?,
                password_hash: row.get(3)?,
                encryption_salt: row.get(4)?,
                callsign: row.get(5)?,
                is_admin: row.get::<_, i64>(6)? != 0,
                is_active: row.get::<_, i64>(7)? != 0,
                theme: row.get(8)?,
                created_at: row.get(9)?,
                updated_at: row.get(10)?,
                last_login_at: row.get(11)?,
            })
        })
        .optional()?;

    Ok(user)
}

/// Get user by ID
pub fn get_user_by_id(conn: &Connection, id: i64) -> Result<Option<User>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT id, username, email, password_hash, encryption_salt, callsign,
               is_admin, is_active, theme, created_at, updated_at, last_login_at
        FROM users WHERE id = ?1
        "#,
    )?;

    let user = stmt
        .query_row([id], |row| {
            Ok(User {
                id: row.get(0)?,
                username: row.get(1)?,
                email: row.get(2)?,
                password_hash: row.get(3)?,
                encryption_salt: row.get(4)?,
                callsign: row.get(5)?,
                is_admin: row.get::<_, i64>(6)? != 0,
                is_active: row.get::<_, i64>(7)? != 0,
                theme: row.get(8)?,
                created_at: row.get(9)?,
                updated_at: row.get(10)?,
                last_login_at: row.get(11)?,
            })
        })
        .optional()?;

    Ok(user)
}

/// List all users (admin only)
pub fn list_users(conn: &Connection) -> Result<Vec<User>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT id, username, email, password_hash, encryption_salt, callsign,
               is_admin, is_active, theme, created_at, updated_at, last_login_at
        FROM users ORDER BY username
        "#,
    )?;

    let users = stmt
        .query_map([], |row| {
            Ok(User {
                id: row.get(0)?,
                username: row.get(1)?,
                email: row.get(2)?,
                password_hash: row.get(3)?,
                encryption_salt: row.get(4)?,
                callsign: row.get(5)?,
                is_admin: row.get::<_, i64>(6)? != 0,
                is_active: row.get::<_, i64>(7)? != 0,
                theme: row.get(8)?,
                created_at: row.get(9)?,
                updated_at: row.get(10)?,
                last_login_at: row.get(11)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(users)
}

/// Update user password
pub fn update_password(conn: &Connection, user_id: i64, new_password: &str) -> Result<()> {
    let password_hash =
        hash_password(new_password).map_err(|e| crate::Error::Other(e.to_string()))?;

    conn.execute(
        "UPDATE users SET password_hash = ?1, updated_at = datetime('now') WHERE id = ?2",
        params![&password_hash, user_id],
    )?;

    Ok(())
}

/// Update user profile (email, callsign)
pub fn update_user_profile(
    conn: &Connection,
    user_id: i64,
    email: Option<&str>,
    callsign: Option<&str>,
) -> Result<()> {
    conn.execute(
        "UPDATE users SET email = ?1, callsign = ?2, updated_at = datetime('now') WHERE id = ?3",
        params![email, callsign, user_id],
    )?;

    Ok(())
}

/// Update user theme preference
pub fn update_user_theme(conn: &Connection, user_id: i64, theme: &str) -> Result<()> {
    // Validate theme value
    if theme != "light" && theme != "dark" {
        return Err(crate::Error::Other(
            "Invalid theme: must be 'light' or 'dark'".into(),
        ));
    }

    conn.execute(
        "UPDATE users SET theme = ?1, updated_at = datetime('now') WHERE id = ?2",
        params![theme, user_id],
    )?;

    Ok(())
}

/// Deactivate user
pub fn deactivate_user(conn: &Connection, user_id: i64) -> Result<()> {
    conn.execute(
        "UPDATE users SET is_active = 0, updated_at = datetime('now') WHERE id = ?1",
        params![user_id],
    )?;
    Ok(())
}

/// Activate user
pub fn activate_user(conn: &Connection, user_id: i64) -> Result<()> {
    conn.execute(
        "UPDATE users SET is_active = 1, updated_at = datetime('now') WHERE id = ?1",
        params![user_id],
    )?;
    Ok(())
}

/// Delete user and all their data
pub fn delete_user(conn: &Connection, user_id: i64) -> Result<()> {
    // CASCADE will handle integrations and watch paths
    conn.execute("DELETE FROM users WHERE id = ?1", params![user_id])?;
    Ok(())
}

/// Record login timestamp
pub fn record_login(conn: &Connection, user_id: i64) -> Result<()> {
    conn.execute(
        "UPDATE users SET last_login_at = datetime('now') WHERE id = ?1",
        params![user_id],
    )?;
    Ok(())
}

/// Get user's encryption salt as fixed-size array
pub fn get_user_encryption_salt(user: &User) -> Result<[u8; 32]> {
    user.encryption_salt
        .as_slice()
        .try_into()
        .map_err(|_| crate::Error::Other("Invalid encryption salt length".into()))
}

/// Count total users
pub fn count_users(conn: &Connection) -> Result<i64> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;
    Ok(count)
}

/// Check if any users exist (for initial setup detection)
pub fn has_users(conn: &Connection) -> Result<bool> {
    Ok(count_users(conn)? > 0)
}

use rusqlite::OptionalExtension;
