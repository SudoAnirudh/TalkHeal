import bcrypt

def init_db():
import sqlite3
import bcrypt
import uuid
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_verified INTEGER DEFAULT 0,
            verification_token TEXT
        )
        """
    )
    conn.commit()
    conn.close()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_verified INTEGER DEFAULT 0,
            verification_token TEXT
        )
    """)
    conn.commit()
    conn.close()

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

def register_user(name, email, password):
    cursor = conn.cursor()
    hashed_pw = hash_password(password)
    try:
        cursor.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", (name, email, hashed_pw))
        conn.commit()
        return True, "User registered successfully"
    except sqlite3.IntegrityError:
        return False, "Email already registered"
    finally:
        conn.close()
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    hashed_pw = hash_password(password)
    verification_token = str(uuid.uuid4())
    try:
        cursor.execute(
            "INSERT INTO users (name, email, password, is_verified, verification_token) VALUES (?, ?, ?, 0, ?)",
            (name, email, hashed_pw, verification_token)
        )
        conn.commit()
        return True, verification_token  # Return token for email sending
    except sqlite3.IntegrityError:
        return False, "Email already registered"
    finally:
        conn.close()

# Function to verify user by token
def verify_user(token):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE verification_token = ? AND is_verified = 0", (token,))
    result = cursor.fetchone()
    if result:
        cursor.execute("UPDATE users SET is_verified = 1, verification_token = NULL WHERE id = ?", (result[0],))
        conn.commit()
        conn.close()
        return True, "Account verified successfully."
    conn.close()
    return False, "Invalid or expired verification token."

def authenticate_user(email, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT name, password FROM users WHERE email = ?", (email,))
    result = cursor.fetchone()
    conn.close()
    if result and check_password(password, result[1]):
        user = {"name": result[0], "email": email}
        return True, user
    return False, None