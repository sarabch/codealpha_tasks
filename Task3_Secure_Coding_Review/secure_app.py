#!/usr/bin/env python3
"""
Secure App - Corrected Version
CodeAlpha Cyber Security Internship - Task 3 (Secure Coding Review)

This file shows the SECURE version of a small user-authentication app,
after fixing the vulnerabilities found during the review:

    1. SQL Injection            -> parameterized queries
    2. Hardcoded credentials    -> loaded from environment variables
    3. Weak password hashing    -> bcrypt (salted, slow hash) instead of md5/sha1
    4. Missing input validation -> basic validation added before using input

Requirements:
    pip install bcrypt
"""

import os
import re
import sqlite3
import bcrypt


# ---------------------------------------------------------------------------
# 2. FIX: no hardcoded credentials.
# Secrets are read from environment variables instead of being written
# in the source code.
# ---------------------------------------------------------------------------
DB_PATH = os.environ.get("APP_DB_PATH", "users.db")
ADMIN_USER = os.environ.get("APP_ADMIN_USER")
ADMIN_PASSWORD = os.environ.get("APP_ADMIN_PASSWORD")  # never stored in plain text


def get_connection():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# 4. FIX: input validation.
# Reject usernames/passwords that are empty, too long, or contain
# unexpected characters, before they ever reach the database or hashing step.
# ---------------------------------------------------------------------------
def is_valid_username(username: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_]{3,20}", username or ""))


def is_valid_password(password: str) -> bool:
    return bool(password) and 8 <= len(password) <= 128


# ---------------------------------------------------------------------------
# 3. FIX: strong password hashing with bcrypt (salted + slow by design),
# instead of a fast, unsalted hash like md5/sha1.
# ---------------------------------------------------------------------------
def hash_password(plain_password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(plain_password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode("utf-8"), password_hash.encode("utf-8")
    )


def register_user(username: str, password: str) -> bool:
    if not is_valid_username(username):
        print("Invalid username. Use 3-20 letters, digits or underscores.")
        return False
    if not is_valid_password(password):
        print("Invalid password. Must be 8-128 characters.")
        return False

    password_hash = hash_password(password)

    conn = get_connection()
    cur = conn.cursor()
    try:
        # ---------------------------------------------------------------
        # 1. FIX: SQL Injection.
        # Parameterized query ("?" placeholders) instead of string
        # concatenation/f-strings. User input is NEVER inserted directly
        # into the SQL string.
        # ---------------------------------------------------------------
        cur.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        print("Username already exists.")
        return False
    finally:
        conn.close()


def authenticate_user(username: str, password: str) -> bool:
    if not is_valid_username(username) or not password:
        return False

    conn = get_connection()
    cur = conn.cursor()
    # Same fix as above: parameterized query, no SQL injection possible.
    cur.execute(
        "SELECT password_hash FROM users WHERE username = ?",
        (username,),
    )
    row = cur.fetchone()
    conn.close()

    if row is None:
        return False

    stored_hash = row[0]
    return verify_password(password, stored_hash)


def main():
    init_db()

    # Example usage - in a real app this would come from a login form / API
    if ADMIN_USER and ADMIN_PASSWORD:
        register_user(ADMIN_USER, ADMIN_PASSWORD)

    print("Secure app initialized. Users table ready with hashed passwords.")


if __name__ == "__main__":
    main()
