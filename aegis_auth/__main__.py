"""Administration from the command line. Passwords are always typed at a prompt (getpass),
never passed as arguments or environment variables.

    python -m aegis_auth init-db                        # create the tables (Oracle; SQLite creates itself)
    python -m aegis_auth create-user admin@example.com --role ADMIN --name "First Admin"
    python -m aegis_auth set-password admin@example.com
    python -m aegis_auth list-users
    python -m aegis_auth unlock admin@example.com       # status ACTIVE, clear failed sign-ins
"""
import argparse
import getpass
import sys

from . import service
from .service import AuthError
from .store import OracleStore, get_store


def _password(confirm: bool = True) -> str:
    first = getpass.getpass("New password: ")
    if confirm and getpass.getpass("Repeat password: ") != first:
        raise AuthError("The passwords do not match.")
    return first


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m aegis_auth", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init-db")
    create = commands.add_parser("create-user")
    create.add_argument("email")
    create.add_argument("--role", default="ANALYST", choices=service.ROLES)
    create.add_argument("--name")
    create.add_argument("--temporary", action="store_true",
                        help="Require a password change at first sign-in")
    reset = commands.add_parser("set-password")
    reset.add_argument("email")
    commands.add_parser("list-users")
    unlock = commands.add_parser("unlock")
    unlock.add_argument("email")
    args = parser.parse_args(argv)
    store = get_store()
    try:
        if args.command == "init-db":
            if isinstance(store, OracleStore):
                print("\n".join(store.create_schema()))
            else:
                print(f"SQLite tables are ready at {store.path}")
        elif args.command == "create-user":
            user = service.create_user(args.email, _password(), args.role, args.name, args.temporary)
            print(f"Created {user['email']} ({user['user_role']}).")
        elif args.command == "set-password":
            user = service.find_user(args.email)
            if not user:
                raise AuthError("No such user.")
            service.set_password(user["user_id"], _password(), must_change=False)
            service.revoke_user_sessions(user["user_id"])
            print("Password changed; existing sessions were signed out.")
        elif args.command == "list-users":
            for user in service.list_users():
                print(f"{user['email']:40} {user['user_role']:8} {user['status']:9} "
                      f"sessions={user['active_sessions']} last sign-in={user['last_login_at'] or '-'}")
        elif args.command == "unlock":
            user = service.find_user(args.email)
            if not user:
                raise AuthError("No such user.")
            service.update_user(user["user_id"], status="ACTIVE")
            store.execute("UPDATE aegis_user_credentials SET failed_attempts = 0, locked_until = NULL "
                          "WHERE user_id = :user_id", {"user_id": user["user_id"]})
            print(f"{user['email']} unlocked.")
    except AuthError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
