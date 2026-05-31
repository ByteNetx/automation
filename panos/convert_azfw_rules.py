import pandas as pd
from pathlib import Path
import json, os, sys, ipaddress, socket
from xlsxwriter.color import Color
from xlsxwriter.utility import xl_col_to_name
from ipaddress import IPv4Address, IPv4Network
from netmiko import ConnectHandler
from netmiko import NetmikoTimeoutException
from netmiko import NetmikoAuthenticationException

basePath = Path.home() / 'pyenv3.13' / 'panos' 
inFile = "config_data/AzureFirewallERAllPolicies.json"
reportFile = "config_data/azfw_rules.xlsx"

def connect(device):
    try:
        net_connect = ConnectHandler(**device)
        prompter = net_connect.find_prompt()
        #if '>' in prompter:
            #net_connect.enable()
        return net_connect
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as error:
        print(error)
        sys.exit()

def validate_ip(target):
    try:
        if "/" in target:
            ipaddress.ip_network(target)
        else:
            ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def resolve_dns(fqdn):
    try:
        socket.gethostbyname(fqdn)
        return True
    except socket.gaierror:
        return False

if os.path.exists(inFile):
    with open(inFile, encoding="utf-8-sig") as f:
        data = json.load(f)
else:
    sys.exit(0)

rules = []
addrObjects = []
servObjects = []
fqdnObjects = []
webCategories = []
for item in data['resources']:
    if "ruleCollectionGroups" in item['type']:
        grpName = item['name'].split("/")[1].strip("')]")
        grpPriority = item['properties']['priority']
        for entry in item['properties']['ruleCollections']:
            collectionName = entry['name']
            collectionPriority = entry['priority']
            action = entry['action']['type']
            for each in entry['rules']:
                rule = {k: v for k,v in each.items() if v}
                protocols = []
                if rule['ruleType'] == 'ApplicationRule' and 'protocols' in rule.keys():
                    if isinstance(rule['protocols'], list) and len(rule['protocols']) != 0:
                        for prot in rule['protocols']:
                            protocols.append(f"{prot['protocolType']}-{prot['port']}")
                        rule['protocols'] = protocols
                rule.update({
                    "action": action,
                    "groupName": grpName,
                    "groupPriority": grpPriority,
                    "collectionName": collectionName,
                    "collectionPriority": collectionPriority
                })
                if rule['ruleType'] == 'NetworkRule' and 'destinationPorts' in rule.keys():
                    services = [v for k, v in rule.items() if k == 'destinationPorts']
                    services = [item for sublist in services for item in sublist]
                    rule['destinationPorts'] = services
                    servObjects.extend(services)
                rules.append(rule)
                addrObjects.extend(v for k, v in rule.items() if k == 'sourceAddresses' or k == 'destinationAddresses')
                if rule['ruleType'] == 'ApplicationRule':
                    fqdnObjects.extend(v for k,v in rule.items() if k == 'targetFqdns' and v)
                    webCategories.extend(v for k,v in rule.items() if k == 'webCategories' and v)

new_rules = []
for each in rules:
    new_rules.append({k: ",".join(map(str, v)) if isinstance(v, list) else v for k, v in each.items()})

sorted_rules = sorted(new_rules, key=lambda x: (x['groupPriority'], x['collectionPriority']))

invalid_ips = []
valid_ips = []
invalid_fqdns = []
valid_fqdns = []
addrObjects = list(set([item for sublist in addrObjects for item in sublist]))
addrObjects = [x for x in addrObjects if x != '*']
for each in addrObjects:
    if validate_ip(each):
        valid_ips.append(each)
    else:
        invalid_ips.append(each)
servObjects = list(set(servObjects))
fqdnObjects = list(set([item for sublist in fqdnObjects for item in sublist]))
for each in fqdnObjects:
    if resolve_dns(each):
        valid_fqdns.append(each)
    else:
        invalid_fqdns.append(each)

webCategories = list(set([item for sublist in webCategories for item in sublist]))

with pd.ExcelWriter(reportFile, engine='xlsxwriter') as writer:
    df_rules = pd.DataFrame(sorted_rules)
    df_rules.fillna('',inplace=True)
    rows = df_rules.shape[0]
    columes = xl_col_to_name(df_rules.shape[1])
    headers = df_rules.columns.tolist()
    df_rules.to_excel(writer, sheet_name='azfw_rules', index=False, )
    workbook = writer.book
    header_format = workbook.add_format({
        'bold': True,
        'italic': False,
        'text_wrap': False,
        'align': 'center',
        'font_color': 'white',
        'bg_color': Color((3,3)),
        'border': 0,
    })
    worksheet1 = writer.sheets['azfw_rules']
    for col_num, value in enumerate(headers):
        worksheet1.write(0, col_num, value, header_format)
    worksheet1.autofit()
    worksheet1.autofilter(f"A1:{columes}{str(rows)}")
    df_obj1 = pd.DataFrame({
        'address_object': valid_ips+valid_fqdns
    })
    headers = df_obj1.columns.tolist()
    df_obj1.to_excel(writer, sheet_name='address_objects', index=False, )
    workbook = writer.book
    worksheet2 = writer.sheets['address_objects']
    worksheet2.autofit()
    df_obj2 = pd.DataFrame({
        'service_object': servObjects
    })
    headers = df_obj2.columns.tolist()
    df_obj2.to_excel(writer, sheet_name='service_object', index=False, )
    workbook = writer.book
    worksheet3 = writer.sheets['service_object']
    worksheet3.autofit()
    df_obj3 = pd.DataFrame({
        'url_category': webCategories
    })
    headers = df_obj3.columns.tolist()
    df_obj3.to_excel(writer, sheet_name='url_category', index=False, )
    workbook = writer.book
    worksheet4 = writer.sheets['url_category']
    worksheet4.autofit()
    df_obj4 = pd.DataFrame({
        'invalid_object': invalid_ips+invalid_fqdns
    })
    headers = df_obj4.columns.tolist()
    df_obj4.to_excel(writer, sheet_name='invalid_object', index=False, )
    workbook = writer.book
    worksheet5 = writer.sheets['invalid_object']
    worksheet5.autofit()

print("\n".join(invalid_ips+invalid_fqdns))
# Validate if the required objects are existing on Panorama
addr = "$\\|".join(addrObjects+fqdnObjects)+"$"
serv = "$\\|".join(servObjects)+"$"
extSERV = []
extADDR = []

net_connect = connect(pan_dev)
print(f"\nConnecting to {pan_dev['host']} and validating objects......")
net_connect.send_command('set cli pager off', expect_string=r'>', delay_factor=4)
net_connect.send_command('set cli config-output-format set', expect_string=r'>', delay_factor=4)
net_connect.send_command('configure', expect_string=r'#', delay_factor=4)

if serv:
    cmd = f"show shared service | match {serv}"
    srv_resp = net_connect.send_command(cmd, expect_string=r'#', delay_factor=4)
    for item in list(filter(None, srv_resp.split('\n'))):
        extSERV.extend(re.findall(r"service\s(\S+)\sprotocol\s(tcp|udp)\sport\s(\S+)", item))
if addr:
    cmd = f"show shared address | match {addr}"
    addr_resp = net_connect.send_command(cmd, expect_string=r'#', delay_factor=4)
    for item in list(filter(None, addr_resp.split('\n'))):
        extADDR.extend(re.findall(r"\saddress\s(\S+)\s\S+\s(\S+)", item))
