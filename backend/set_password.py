"""
Set a password for an existing user, straight in the local database.

A development tool. The real reset flow goes through mail and a
single-use token; this exists so you are not stuck when the mailbox is
out of reach, and it needs access to the database file itself, so it
cannot be run remotely.

    python set_password.py                       # list the users
    python set_password.py you@example.com       # prompts for a password
    python set_password.py you@example.com Sod123456
"""
from __future__ import annotations

import sys
from getpass import getpass

from database import SessionLocal, init_db
from models import User
from API.auth import hash_password

MIN_LENGTH = 8   # same as RegisterRequest in schemas.py


def list_users(db) -> None:
    users = db.query(User).order_by(User.id).all()
    if not users:
        print("No users yet. Register through the extension popup or login.html.")
        return
    print(f"\n{len(users)} user(s):\n")
    for u in users:
        has_pw = "has a password" if u.password_hash else "no password (created by a scan)"
        print(f"  {u.email:<38} {u.name or '':<18} {has_pw}")
    print("\nto set one:  python set_password.py <address>\n")


def main() -> None:
    init_db()
    db = SessionLocal()
    try:
        if len(sys.argv) < 2:
            list_users(db)
            return

        email = sys.argv[1].strip().lower()
        user = db.query(User).filter(User.email == email).first()
        if not user:
            print(f"No user with the address {email}.")
            list_users(db)
            sys.exit(1)

        if len(sys.argv) >= 3:
            password = sys.argv[2]
        else:
            password = getpass("new password: ")
            if password != getpass("again: "):
                sys.exit("The passwords do not match.")

        if len(password) < MIN_LENGTH:
            sys.exit(f"The password must be at least {MIN_LENGTH} characters.")

        user.password_hash = hash_password(password)
        db.commit()
        print(f"\nPassword updated for {user.email}.")
        print("You can sign in now in the extension popup and on the site.\n")
    finally:
        db.close()


if __name__ == "__main__":
    main()
