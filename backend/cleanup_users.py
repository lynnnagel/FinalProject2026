"""
ניקוי חשבונות שנוצרו בטעות מכתובות של שולחים.

הרקע: סקריפט התוכן של התוסף זיהה את בעל התיבה על ידי חיפוש
`[data-hovercard-id]` ו-`[email]` בכל הדף. גוגל תולה את המאפיינים האלה
על כל שבב של אדם, כולל שולחי המיילים, ולכן הכתובת שנבחרה הייתה בדרך
כלל של שולח כלשהו. /scan יוצר משתמש חדש לכל כתובת שאינה מוכרת, וכך
נוצרו במסד חשבונות בשמות noreply@discord.com ו-info@wolt.com, עם
הסריקות רשומות תחתיהם.

הבאג תוקן ב-content.js. הסקריפט הזה מנקה את מה שכבר נוצר.

הרצה (מתוך backend/):
    python cleanup_users.py                    # מציג בלבד, לא משנה דבר
    python cleanup_users.py --delete           # מוחק אחרי אישור
    python cleanup_users.py --delete --yes     # בלי לשאול

למחיקת חשבונות ששמם ידוע, כולל רשומים — למשל אלה שנוצרו ב-check_demo.py:
    python cleanup_users.py --emails demo-user@example.com --delete
"""
from __future__ import annotations

import argparse

from database import SessionLocal, init_db
from models import User, EmailRecord, Alert


def suspect_users(db) -> list[User]:
    """
    חשבונות ללא סיסמה שאינם משמשים כמפקח על אף אחד.

    היעדר סיסמה פירושו שהחשבון לא נוצר בהרשמה אלא אוטומטית בסריקה.
    חשבון שמשמש כמפקח נשמר בכל מקרה — הקישור אליו נעשה במפורש.
    """
    guardian_ids = {
        gid for (gid,) in db.query(User.guardian_id).filter(User.guardian_id.isnot(None))
    }
    return [
        u for u in db.query(User).order_by(User.id).all()
        if not u.password_hash and u.id not in guardian_ids
    ]


def main() -> None:
    ap = argparse.ArgumentParser(description="ניקוי חשבונות שנוצרו מכתובות שולחים")
    ap.add_argument("--delete", action="store_true", help="למחוק בפועל")
    ap.add_argument("--yes", action="store_true", help="לא לשאול לאישור")
    ap.add_argument("--keep", nargs="*", default=[],
                    help="כתובות לשמור גם אם אין להן סיסמה")
    ap.add_argument("--emails", nargs="*", default=[],
                    help="למחוק כתובות מסוימות, גם אם יש להן סיסמה "
                         "(למשל חשבונות הבדיקה של check_demo.py)")
    args = ap.parse_args()

    init_db()
    db = SessionLocal()
    try:
        keep = {e.strip().lower() for e in args.keep}

        # Named addresses are deleted whether or not they have a
        # password. The automatic sweep below never touches a registered
        # account, which is the right default - but the check scripts
        # register real accounts, and those are worth being able to
        # clear by name after a rehearsal.
        if args.emails:
            wanted = {e.strip().lower() for e in args.emails}
            targets = [u for u in db.query(User).order_by(User.id).all()
                       if u.email.lower() in wanted]
            if not targets:
                print("\nאף אחת מהכתובות שביקשת אינה במסד.\n")
                return
        else:
            targets = [u for u in suspect_users(db) if u.email.lower() not in keep]

        registered = db.query(User).filter(User.password_hash.isnot(None)).count()
        print(f"\n{registered} חשבונות רשומים (עם סיסמה) — הם לא ייגעו.\n")

        if not targets:
            print("אין חשבונות למחיקה.\n")
            return

        print(f"{len(targets)} חשבונות "
              f"{'שביקשת למחוק' if args.emails else 'שנוצרו אוטומטית'}:\n")
        total_emails = 0
        for u in targets:
            n = db.query(EmailRecord).filter(EmailRecord.user_id == u.id).count()
            total_emails += n
            print(f"  {u.email:<40} {n:>4} סריקות")

        print(f"\nסך הכול {total_emails} רשומות סריקה ישויכו למחיקה.")

        if not args.delete:
            print("\nלא נמחק דבר. להרצה בפועל:")
            print("    python cleanup_users.py --delete")
            print("לשמירת כתובת מסוימת:")
            print("    python cleanup_users.py --delete --keep me@example.com\n")
            return

        if not args.yes:
            answer = input("\nלמחוק? הקלידי כן לאישור: ").strip()
            if answer not in ("כן", "yes", "y"):
                print("בוטל.\n")
                return

        for u in targets:
            db.query(Alert).filter(Alert.user_id == u.id).delete(synchronize_session=False)
            db.query(EmailRecord).filter(EmailRecord.user_id == u.id).delete(
                synchronize_session=False
            )
            db.delete(u)
        db.commit()
        print(f"\nנמחקו {len(targets)} חשבונות ו-{total_emails} רשומות סריקה.\n")
    finally:
        db.close()


if __name__ == "__main__":
    main()
