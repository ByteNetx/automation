import json
import pandas as pd
import sys
from pathlib import Path

def flatten_list(value):
    """Convert a list to a comma-separated string, or return empty string."""
    if isinstance(value, list):
        return ', '.join(value)
    return value if value else ''

def boolean_to_string(value):
    """Convert boolean to 'true'/'false' string."""
    if isinstance(value, bool):
        return 'true' if value else 'false'
    return str(value).lower() if value is not None else 'false'

def json_to_excel(json_path, excel_path=None):
    """Convert SCM JSON to Excel file with three sheets."""
    if excel_path is None:
        excel_path = Path(json_path).with_suffix('.xlsx')

    # Load JSON
    with open(json_path, 'r') as f:
        data = json.load(f)

    # Prepare rows for each sheet
    addresses_rows = []
    addr_groups_rows = []
    services_rows = []
    serv_groups_rows = []
    rules_rows = []

    for scope, content in data.items():
        if content.get('type') != 'folder' and content.get('type') != 'snippet':
            continue  # skip non-scope entries if any

        # Addresses
        for addr in content.get('addresses', []):
            row = {
                content.get('type'): scope,
                'name': addr.get('name', ''),
                'description': addr.get('description', ''),
                'ip_netmask': addr.get('ip_netmask', ''),
                'fqdn': addr.get('fqdn', '')
            }
            addresses_rows.append(row)

        # Address Groups
        for grp in content.get('address-groups', []):
            row = {
                content.get('type'): scope,
                'name': grp.get('name', ''),
                'description': grp.get('description', ''),
                'static': flatten_list(grp.get('static', []))
            }
            addr_groups_rows.append(row)

        # Services
        for serv in content.get('services', []):
            proto_name = list(serv.get('protocol').keys())[0]
            port_num = serv.get('protocol').get(proto_name).get('port')
            row = {
                content.get('type'): scope,
                'name': serv.get('name', ''),
                'description': serv.get('description', ''),
                'protocol': proto_name,
                "port": port_num
            }
            services_rows.append(row)

        # Service Groups
        for grp in content.get('service-groups', []):
            row = {
                content.get('type'): scope,
                'name': grp.get('name', ''),
                'description': grp.get('description', ''),
                'members': flatten_list(grp.get('members', []))
            }
            serv_groups_rows.append(row)

        # Security Rules
        for rule in content.get('security-rules', []):
            # Extract profile_setting group
            profile_group = rule.get('profile_setting', {}).get('group', [])
            row = {
                content.get('type'): scope,
                'position': rule.get('position', 'post'),
                'policy_type': rule.get('policy_type', 'Security'),
                'name': rule.get('name', ''),
                'disabled': boolean_to_string(rule.get('disabled', False)),
                'description': rule.get('description', ''),
                'tag': flatten_list(rule.get('tag', [])),
                'from': flatten_list(rule.get('from', [])),
                'to': flatten_list(rule.get('to', [])),
                'source': flatten_list(rule.get('source', [])),
                'negate_source': boolean_to_string(rule.get('negate_source', False)),
                'source_user': flatten_list(rule.get('source_user', ['any'])),
                'destination': flatten_list(rule.get('destination', [])),
                'service': flatten_list(rule.get('service', ['application-default'])),
                'negate_destination': boolean_to_string(rule.get('negate_destination', False)),
                'source_hip': flatten_list(rule.get('source_hip', ['any'])),
                'destination_hip': flatten_list(rule.get('destination_hip', ['any'])),
                'application': flatten_list(rule.get('application', [])),
                'category': flatten_list(rule.get('category', ['any'])),
                'profile_setting_group': flatten_list(profile_group),
                'log_setting': rule.get('log_setting', 'logging'),
                'log_start': boolean_to_string(rule.get('log_start', False)),
                'log_end': boolean_to_string(rule.get('log_end', True))
            }
            rules_rows.append(row)

    # Create DataFrames
    df_addresses = pd.DataFrame(addresses_rows)
    df_addr_groups = pd.DataFrame(addr_groups_rows)
    df_services = pd.DataFrame(services_rows)
    df_serv_groups = pd.DataFrame(serv_groups_rows) 
    df_rules = pd.DataFrame(rules_rows)

    # Write to Excel
    with pd.ExcelWriter(excel_path, engine='openpyxl') as writer:
        df_addresses.to_excel(writer, sheet_name='Addresses', index=False)
        df_addr_groups.to_excel(writer, sheet_name='AddressGroups', index=False)
        df_services.to_excel(writer, sheet_name='Services', index=False)
        df_serv_groups.to_excel(writer, sheet_name='ServiceGroups', index=False)
        df_rules.to_excel(writer, sheet_name='SecurityRules', index=False)

    print(f"Excel file generated successfully at {excel_path}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python json_to_excel.py <json_file_path> [output_excel_path]")
        sys.exit(1)
    json_file = sys.argv[1]
    out_file = sys.argv[2] if len(sys.argv) > 2 else None
    json_to_excel(json_file, out_file)
