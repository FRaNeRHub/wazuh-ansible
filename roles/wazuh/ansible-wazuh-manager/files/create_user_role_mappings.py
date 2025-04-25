import logging
import sys
import json
import random
import string
import os

# Set framework path
sys.path.append(os.path.dirname(sys.argv[0]) + "/../framework")

if '--role' in sys.argv:
    index = sys.argv.index('--role')
    try:
        role = sys.argv[index + 1]
    except IndexError:
        print("Error: No value for --role")
        sys.exit(1)
else:
    print("Error: No value for --role")
    sys.exit(1)

if '--user' in sys.argv:
    index = sys.argv.index('--user')
    try:
        user = sys.argv[index + 1]
    except IndexError:
        print("Error: No value for --user")
        sys.exit(1)
else:
    print("Error: No value for --user")
    sys.exit(1)

if '--tenant' in sys.argv:
    index = sys.argv.index('--tenant')
    try:
        tenant = sys.argv[index + 1]
    except IndexError:
        print("Error: No value for --tenant")
        sys.exit(1)
else:
    print("Error: No value for --tenant")
    sys.exit(1)


try:
    from wazuh.rbac.orm import check_database_integrity
    from wazuh.security import (
        add_policy,
        add_role,
        add_rule,
        set_role_policy,
        set_role_rule,
        get_roles,
        get_rules,
        get_users,
        get_policies
    )
except Exception as e:
    logging.error("No module 'wazuh' found.")
    sys.exit(1)


def get_role_id(name):
    role = get_roles(search_text=f'{name.lower()}', search_in_fields=['name'])
    if len(role._affected_items) > 0:
        return(role._affected_items[0]['id'])
    else:
        return(False)

def get_rule_id(name):
    rule = get_rules(search_text=name, search_in_fields=['name'])
    if len(rule._affected_items) > 0:
        return(rule._affected_items[0]['id'])
    else:
        return(False)



if __name__ == "__main__":
    # create RBAC database
    check_database_integrity()

    role_id = get_role_id(f'{tenant.lower()}_read_role')
    rule_id = get_rule_id(f'{user}_to_{role.lower()}')

    # Create rule if needed
    if not rule_id:
        rule = {
            'FIND': {
                'user_name': f'{user}'
            }
        }
        add_rule(name=f'{user}_to_{role.lower()}', rule=rule)
        rule_id = get_rule_id(f'{user}_to_{role.lower()}')

    # Set role for rule
    set_role_rule(role_id=str(role_id), rule_ids=[str(rule_id)])