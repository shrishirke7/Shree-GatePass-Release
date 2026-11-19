import argparse
import getpass
import json
import os

import psycopg
from werkzeug.security import generate_password_hash


def main():
    parser = argparse.ArgumentParser(description="Reset Super Admin or Organization Admin password")
    parser.add_argument("--org", default="", help="Organization slug (omit to reset Platform Super Admin)")
    args = parser.parse_args()

    username = getpass.getpass("Username: ").strip()
    password = getpass.getpass("New password (hidden): ")
    confirmation = getpass.getpass("Confirm new password (hidden): ")
    if len(password) < 8 or len(password) > 1024:
        raise SystemExit("Password must be between 8 and 1024 characters.")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")

    with psycopg.connect(os.environ["DATABASE_URL"], connect_timeout=8) as conn:
        with conn.cursor() as cur:
            if not args.org:
                cur.execute("SELECT value FROM app_state WHERE key='super_admins' FOR UPDATE")
                row = cur.fetchone()
                supers = row[0] if row else []
                acc = next((s for s in supers if str(s.get("username", "")).casefold() == username.casefold()), None)
                if not acc:
                    raise SystemExit("Super Admin account not found.")
                acc["password_hash"] = generate_password_hash(password)
                acc["auth_version"] = int(acc.get("auth_version", 0) or 0) + 1
                cur.execute("UPDATE app_state SET value=%s::jsonb, updated_at=now() WHERE key='super_admins'", (json.dumps(supers),))
                print("Super Admin password reset complete.")
                return

            cur.execute("SELECT id FROM organizations WHERE LOWER(slug)=LOWER(%s) LIMIT 1", (args.org,))
            org_row = cur.fetchone()
            if not org_row:
                raise SystemExit(f"Organization '{args.org}' not found.")
            oid = org_row[0]
            cur.execute("SELECT value FROM org_state WHERE org_id=%s AND key='manual_users' FOR UPDATE", (oid,))
            row = cur.fetchone()
            users = row[0] if row else []
            acc = next(
                (u for u in users if str(u.get("username", "")).casefold() == username.casefold() and u.get("role") == "Administrator"),
                None,
            )
            if not acc:
                raise SystemExit("Enabled organization administrator not found.")
            acc["password_hash"] = generate_password_hash(password)
            acc["auth_version"] = int(acc.get("auth_version", 0) or 0) + 1
            cur.execute("UPDATE org_state SET value=%s::jsonb, updated_at=now() WHERE org_id=%s AND key='manual_users'", (json.dumps(users), oid))
            print(f"Administrator password reset complete for org '{args.org}'.")


if __name__ == "__main__":
    main()
