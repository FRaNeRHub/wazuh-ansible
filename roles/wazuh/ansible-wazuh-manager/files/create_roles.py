import logging
import sys
import json
import random
import string
import os

# Set framework path
sys.path.append(os.path.dirname(sys.argv[0]) + "/../framework")

if '--tenant' in sys.argv:
    index = sys.argv.index('--tenant')
    try:
        tenant = sys.argv[index + 1]
    except IndexError:
        print("Error: No value for --tenant")
        sys.exit(1)

try:
    from wazuh.rbac.orm import check_database_integrity
    from wazuh.security import (
        add_policy,
        add_role,
        set_role_policy,
        get_roles,
        get_policies
    )
except Exception as e:
    logging.error("No module 'wazuh' found.")
    sys.exit(1)

def get_policy_id(name):
    policy = get_policies(search_text=f'{tenant.lower()}_read_policy', search_in_fields=['name'])
    return(policy._affected_items[0]['id'])

def get_role_id(name):
    role = get_roles(search_text=f'{tenant.lower()}_read_role', search_in_fields=['name'])
    return(role._affected_items[0]['id'])


if __name__ == "__main__":
    # create RBAC database
    check_database_integrity()

    policies = get_policies()
    roles = get_roles()

    policy_exists = any(policy['name'] == f'{tenant.lower()}_read_policy' for policy in policies._affected_items)

    if not policy_exists:
        print("Creating policy")
        policy = {
            'actions': ['agent:read'],
            'resources': [f'agent:group:{tenant}'],
            'effect': 'allow'
        }
        add_policy(name=f'{tenant.lower()}_read_policy', policy=policy)

    role_exists = any(role['name'] == f'{tenant.lower()}_read_role' for role in roles._affected_items)

    if not role_exists:
        add_role(f'{tenant.lower()}_read_role')
        role_id = str(get_role_id(f'{tenant.lower()}_read_role'))
        policy_id = str(get_policy_id(f'{tenant.lower()}_read_policy'))
        result = set_role_policy(role_id=role_id, policy_ids=[policy_id])

    