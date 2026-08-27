"""
Clear accounts that were created by mistake from sender addresses.

The extension used to identify the mailbox owner by scanning the page
for [data-hovercard-id] and [email]. Google hangs those on every person
chip, senders included, so the address picked was usually a sender's -
and /scan creates a user for any address it does not know. The bug is
fixed in content.js; this clears what it left behind.

    python cleanup_users.py                    # list only, changes nothing
    python cleanup_users.py --delete           # delete, after confirming
    python cleanup_users.py --delete --yes     # no confirmation

To delete named accounts, registered ones included - the ones
check_demo.py creates, for instance:
    python cleanup_users.py --emails demo-user@example.com --delete
"""
from __future__ import annotations

import argparse

from database import SessionLocal, init_db
from models import User, EmailRecord, Alert


def suspect_users(db) -> list[User]:
    """
    Accounts with no password that are nobody's guardian.

    No password means the account came from a scan rather than a
    registration. A guardian is kept regardless - that link was made
    deliberately.
    """
    guardian_ids = {
        gid for (gid,) in db.query(User.guardian_id).filter(User.guardian_id.isnot(None))
    }
    return [
        u for u in db.query(User).order_by(User.id).all()
        if not u.password_hash and u.id not in guardian_ids
    ]


def main() -> None:
    ap = argparse.ArgumentParser(description="clear accounts created from sender addresses")
    ap.add_argument("--delete", action="store_true", help="actually delete")
    ap.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    ap.add_argument("--keep", nargs="*", default=[],
                    help="addresses to keep even with no password")
    ap.add_argument("--emails", nargs="*", default=[],
                    help="delete these addresses, password or not")
    args = ap.parse_args()

    init_db()
    db = SessionLocal()
    try:
        keep = {e.strip().lower() for e in args.keep}

        # The sweep below never touches a registered account, which is
        # the right default - but the check scripts register real ones.
        if args.emails:
            wanted = {e.strip().lower() for e in args.emails}
            targets = [u for u in db.query(User).order_by(User.id).all()
                       if u.email.lower() in wanted]
            if not targets:
                print("\nNone of those addresses are in the database.\n")
                return
        else:
            targets = [u for u in suspect_users(db) if u.email.lower() not in keep]

        registered = db.query(User).filter(User.password_hash.isnot(None)).count()
        print(f"\n{registered} registered account(s) - untouched.\n")

        if not targets:
            print("Nothing to delete.\n")
            return

        print(f"{len(targets)} account(s) "
              f"{'you named' if args.emails else 'created automatically'}:\n")
        total_emails = 0
        for u in targets:
            n = db.query(EmailRecord).filter(EmailRecord.user_id == u.id).count()
            total_emails += n
            print(f"  {u.email:<40} {n:>4} scans")

        print(f"\n{total_emails} scan record(s) will go with them.")

        if not args.delete:
            print("\nNothing was deleted. To do it:")
            print("    python cleanup_users.py --delete")
            print("To keep one address:")
            print("    python cleanup_users.py --delete --keep me@example.com\n")
            return

        if not args.yes:
            answer = input("\nDelete? type yes to confirm: ").strip().lower()
            if answer not in ("yes", "y", "כן"):
                print("Cancelled.\n")
                return

        for u in targets:
            db.query(Alert).filter(Alert.user_id == u.id).delete(synchronize_session=False)
            db.query(EmailRecord).filter(EmailRecord.user_id == u.id).delete(
                synchronize_session=False
            )
            db.delete(u)
        db.commit()
        print(f"\nDeleted {len(targets)} account(s) and {total_emails} scan record(s).\n")
    finally:
        db.close()


if __name__ == "__main__":
    main()
