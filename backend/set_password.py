"""
קביעת סיסמה למשתמש קיים, ישירות במסד הנתונים המקומי.

כלי פיתוח. זרימת האיפוס הרגילה עוברת במייל ובאסימון חד-פעמי
(/auth/forgot-password), וזו הזרימה שהמשתמשים משתמשים בה. הסקריפט הזה
קיים כדי לא להיתקע במהלך פיתוח כשאין גישה לתיבה, והוא דורש גישה
לקובץ המסד עצמו — כלומר לא ניתן להפעילו מרחוק.

הרצה (מתוך backend/):
    python set_password.py                       # מציג את המשתמשים הקיימים
    python set_password.py you@example.com       # מבקש סיסמה חדשה
    python set_password.py you@example.com Sod123456
"""
from __future__ import annotations

import sys
from getpass import getpass

from database import SessionLocal, init_db
from models import User
from API.auth import hash_password

MIN_LENGTH = 8   # זהה ל-RegisterRequest ב-schemas.py


def list_users(db) -> None:
    users = db.query(User).order_by(User.id).all()
    if not users:
        print("אין משתמשים במסד. הירשמי דרך הפופאפ של התוסף או דרך login.html.")
        return
    print(f"\n{len(users)} משתמשים:\n")
    for u in users:
        has_pw = "יש סיסמה" if u.password_hash else "בלי סיסמה (נוצר אוטומטית בסריקה)"
        print(f"  {u.email:<38} {u.name or '':<18} {has_pw}")
    print("\nלקביעת סיסמה:  python set_password.py <כתובת>\n")


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
            print(f"לא נמצא משתמש בכתובת {email}.")
            list_users(db)
            sys.exit(1)

        if len(sys.argv) >= 3:
            password = sys.argv[2]
        else:
            password = getpass("סיסמה חדשה: ")
            if password != getpass("שוב: "):
                sys.exit("הסיסמאות אינן תואמות.")

        if len(password) < MIN_LENGTH:
            sys.exit(f"הסיסמה חייבת להכיל לפחות {MIN_LENGTH} תווים.")

        user.password_hash = hash_password(password)
        db.commit()
        print(f"\nהסיסמה של {user.email} עודכנה.")
        print("אפשר להתחבר עכשיו בפופאפ של התוסף ובאתר.\n")
    finally:
        db.close()


if __name__ == "__main__":
    main()
