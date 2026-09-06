import pandas as pd
import json
import sys
from pathlib import Path

def parse_boolean(value):
    """Convert string 'true'/'false' or bool to Python bool."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() == 'true'
    return bool(value)

def parse_list(value):
    """Convert comma-separated string or list to a Python list."""
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [item.strip() for item in value.split(',') if item.strip()]
    return []

def build_address(row):
    """Build an address object from a row of the Addresses sheet."""
    addr = {
        "name": row['name'],
        "description": row.get('description', 'Created by SCM API 0903')
    }
    ip_netmask = row.get('ip_netmask', '')
    fqdn = row.get('fqdn', '')
    if ip_netmask:
        addr["ip_netmask"] = ip_netmask
    elif fqdn:
        addr["fqdn"] = fqdn
    else:
        raise ValueError(f"Address '{row['name']}' must have either ip_netmask or fqdn.")
    return addr

def build_address_group(row):
    """Build an address-group object from a row of the AddressGroups sheet."""
    members = parse_list(row.get('static', ''))
    return {
        "name": row['name'],
        "description": row.get('description', 'Created by SCM API 0903'),
        "static": members
    }

def build_service(row):
    """Build an service object from a row of the Services sheet."""
    serv = {
        "name": row['name'],
        "description": row.get('description', 'Created by SCM API 0903'),
    }
    protocol = row.get('protocol', '')
    port = row.get('port', '')
    if protocol and port:
        serv["protocol"] = {
            protocol: {"port": port}
        }
    else:
        raise ValueError(f"Service '{row['name']}' must have both protocol and port.")
    return serv

def build_service_group(row):
    """Build an service-group object from a row of the ServiceGroups sheet."""
    members = parse_list(row.get('members', ''))
    return {
        "name": row['name'],
        "description": row.get('description', 'Created by SCM API 0903'),
        "members": members
    }

def build_edl(row):
    """Build an EDL object from a row of the EDLs sheet."""
    edl = {
        "name": row['name']
    }
    edl_type = row.get('type', '')
    username = row.get('username', '')
    password = row.get('password', '')
    recurring = row.get('recurring', 'hourly')
    if edl_type:
        if username and password:
            auth = {
                  "username": row.get('username', 'None'),
                  "password": row.get('password', 'None')
                }
        else:
            auth = {}
        edl["type"] = {
            edl_type: {
                "description": row.get('description', 'Created by SCM API 0903'),
                "url": row.get('url'),
                "certificate_profile": row.get('certificate_profile', 'None'),
                "auth": auth,
                "recurring": {
                  recurring: {}
                }
            }
        }
    else:
        raise ValueError(f"EDL '{row['name']}' must be, ip, domain or url.")
    return edl

def build_security_rule(row):
    """Build a security-rule object from a row of the SecurityRules sheet."""
    rule = {
        "position": row.get('position', 'post'),
        "policy_type": row.get('policy_type', 'Security'),
        "name": row['name'],
        "disabled": parse_boolean(row.get('disabled', False)),
        "description": row.get('description', 'Created by SCM API 0903'),
        "tag": parse_list(row.get('tag', '')),
        "from": parse_list(row.get('from', 'any')),
        "to": parse_list(row.get('to', 'any')),
        "source": parse_list(row.get('source', 'any')),
        "negate_source": parse_boolean(row.get('negate_source', False)),
        "source_user": parse_list(row.get('source_user', 'any')),
        "destination": parse_list(row.get('destination', 'any')),
        "service": parse_list(row.get('service', 'application-default')),
        "negate_destination": parse_boolean(row.get('negate_destination', False)),
        "source_hip": parse_list(row.get('source_hip', 'any')),
        "destination_hip": parse_list(row.get('destination_hip', 'any')),
        "application": parse_list(row.get('application', 'any')),
        "category": parse_list(row.get('category', 'any')),
        "profile_setting": {
            "group": parse_list(row.get('profile_setting_group', 'best-practice'))
        },
        "log_setting": row.get('log_setting', 'logging'),
        "log_start": parse_boolean(row.get('log_start', False)),
        "log_end": parse_boolean(row.get('log_end', True))
    }
    return rule

def generate_json_from_excel(excel_path, output_path=None):
    """Read Excel file and produce the JSON structure."""
    if output_path is None:
        output_path = Path(excel_path).with_suffix('.json')

    # Read sheets
    try:
        addresses_df = pd.read_excel(excel_path, sheet_name='Addresses')
        addresses_df.fillna('', inplace=True)
    except ValueError:
        addresses_df = pd.DataFrame()  # empty if sheet missing
    try:
        addr_groups_df = pd.read_excel(excel_path, sheet_name='AddressGroups')
        addr_groups_df.fillna('', inplace=True)
    except ValueError:
        addr_groups_df = pd.DataFrame()
    try:
        services_df = pd.read_excel(excel_path, sheet_name='Services')
        services_df.fillna('', inplace=True)
    except ValueError:
        services_df = pd.DataFrame()  # empty if sheet missing
    try:
        serv_groups_df = pd.read_excel(excel_path, sheet_name='ServiceGroups')
        serv_groups_df.fillna('', inplace=True)
    except ValueError:
        serv_groups_df = pd.DataFrame()
    try:
        edls_df = pd.read_excel(excel_path, sheet_name='EDLs')
        edls_df.fillna('', inplace=True)
    except ValueError:
        edls_df = pd.DataFrame()  # empty if sheet missing
    try:
        rules_df = pd.read_excel(excel_path, sheet_name='SecurityRules')
        rules_df.fillna('', inplace=True)
    except ValueError:
        rules_df = pd.DataFrame()

    # Initialize result dictionary
    result = {}

    # Process addresses
    for _, row in addresses_df.iterrows():
        folder = row.get('folder')
        if not folder:
            continue
        if folder not in result:
            result[folder] = {"type": "folder", "addresses": [], "address-groups": [], "services": [], "service-groups": [], "external-dynamic-lists": [], "security-rules": []}
        addr = build_address(row)
        result[folder]["addresses"].append(addr)

    # Process address groups
    for _, row in addr_groups_df.iterrows():
        folder = row.get('folder')
        if not folder:
            continue
        if folder not in result:
            result[folder] = {"type": "folder", "addresses": [], "address-groups": [], "services": [], "service-groups": [], "external-dynamic-lists": [], "security-rules": []}
        grp = build_address_group(row)
        result[folder]["address-groups"].append(grp)

    # Process service
    for _, row in services_df.iterrows():
        folder = row.get('folder')
        if not folder:
            continue
        if folder not in result:
            result[folder] = {"type": "folder", "addresses": [], "address-groups": [], "services": [], "service-groups": [], "external-dynamic-lists": [], "security-rules": []}
        serv = build_service(row)
        result[folder]["services"].append(serv)

    # Process service groups
    for _, row in serv_groups_df.iterrows():
        folder = row.get('folder')
        if not folder:
            continue
        if folder not in result:
            result[folder] = {"type": "folder", "addresses": [], "address-groups": [], "services": [], "service-groups": [], "external-dynamic-lists": [], "security-rules": []}
        grp = build_service_group(row)
        result[folder]["service-groups"].append(grp)

    # Process edl
    for _, row in edls_df.iterrows():
        folder = row.get('folder')
        snippet = row.get('snippet', '')
        if not folder and not snippet:
            continue
        if folder:
            if folder not in result:
                result[folder] = {"type": "folder", "addresses": [], "address-groups": [], "services": [], "service-groups": [], "external-dynamic-lists": [], "security-rules": []}
            edl = build_edl(row)
            result[folder]["external-dynamic-lists"].append(edl)
        elif snippet:
            if snippet not in result:
                result[snippet] = {"type": "snippet", "addresses": [], "address-groups": [], "services": [], "service-groups": [], "external-dynamic-lists": [], "security-rules": []}
            edl = build_edl(row)
            result[snippet]["external-dynamic-lists"].append(edl)

    # Process security rules
    for _, row in rules_df.iterrows():
        folder = row.get('folder', '')
        snippet = row.get('snippet', '')
        if not folder and not snippet:
            continue
        if folder:
            if folder not in result:
                result[folder] = {"type": "folder", "addresses": [], "address-groups": [], "services": [], "service-groups": [], "external-dynamic-lists": [], "security-rules": []}
            rule = build_security_rule(row)
            result[folder]["security-rules"].append(rule)
        elif snippet:
            if snippet not in result:
                result[snippet] = {"type": "snippet", "addresses": [], "address-groups": [], "services": [], "service-groups": [], "external-dynamic-lists": [], "security-rules": []}
            rule = build_security_rule(row)
            result[snippet]["security-rules"].append(rule)

    for scope, objects in result.items():
        result[scope] = {k: v for k, v in objects.items() if v}

    # Write JSON
    with open(output_path, 'w') as f:
        json.dump(result, f, indent=4)
    print(f"JSON generated successfully at {output_path}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python generate_scm_json.py <excel_file_path> [output_json_path]")
        sys.exit(1)
    excel_file = sys.argv[1]
    out_file = sys.argv[2] if len(sys.argv) > 2 else None
    generate_json_from_excel(excel_file, out_file)
