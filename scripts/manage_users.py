#!/usr/bin/env python3
"""Privileged local recovery/provisioning. Passwords are prompted, never CLI arguments."""
import argparse
import getpass
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from modules.identity import IdentityStore, ROLES  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', required=True, help='Managed identity database configured by AUTH_USERS_DB')
    parser.add_argument('operation', choices=('create','reset-password','revoke','list'))
    parser.add_argument('username', nargs='?')
    parser.add_argument('--role', choices=sorted(ROLES), default='viewer')
    args = parser.parse_args()
    if args.operation != 'list' and not args.username:
        parser.error('username is required')
    store = IdentityStore(args.db)
    actor = 'local-operator:' + getpass.getuser()
    try:
        if args.operation == 'list':
            print(json.dumps(store.list_users(), indent=2))
            return 0
        if args.operation == 'revoke':
            store.change(args.username, actor=actor, reason='Local operator session recovery', revoke=True)
        else:
            password = getpass.getpass('New password (12–256 characters): ')
            if password != getpass.getpass('Confirm password: '):
                raise ValueError('Passwords do not match.')
            if args.operation == 'create':
                store.create(args.username, password, args.role, actor=actor, reason='Local operator provisioning')
            else:
                store.change(args.username, actor=actor, reason='Local operator password recovery', password=password)
        print('Identity change recorded; existing sessions revoked where applicable.')
        return 0
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1
    finally:
        store.close()


if __name__ == '__main__':
    sys.exit(main())
