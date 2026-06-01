import pandas as pd
from pathlib import Path
import json, os, sys, ipaddress, socket
import argparse, jinja2, re, getpass
from xlsxwriter.color import Color
from xlsxwriter.utility import xl_col_to_name
from NetDev import NetworkDevice

dataFilePath = Path.home() / 'pyenv3.13' / 'panos' / 'config_data'
cfgFilePath = Path.home() / 'pyenv3.13' / 'panos' / 'config_file'

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
    except:
        return False

def createConfig(data, loc, pano, cfgFile) -> dict:
    orig_rules = []
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
                    rule.update({
                        "action": action,
                        "groupName": grpName,
                        "groupPriority": grpPriority,
                        "collectionName": collectionName,
                        "collectionPriority": collectionPriority
                    })
                    if rule['ruleType'] == 'ApplicationRule' and 'protocols' in rule.keys():
                        app = [prot.get('protocolType')+'-'+str(prot.get('port')) for prot in rule['protocols']]
                        rule['protocols'] = app
                    orig_rules.append(rule)
    
    rules = sorted(orig_rules, key=lambda x: (x['groupPriority'], x['collectionPriority']))

    #Validate objects referenced in the Azure firewall rules
    orig_servObj = []
    orig_addrObj = []
    orig_fqdn = []
    orig_url = []

    for each in rules:
        rule = {k: v for k,v in each.items() if v}
        if rule['ruleType'] == 'NetworkRule':
            rule_serv = [v for k, v in rule.items() if k == 'destinationPorts']
            services = [item for sublist in rule_serv for item in sublist]
            orig_servObj.extend(services)
            rule_addr = [v for k, v in rule.items() if k == 'sourceAddresses' or k == 'destinationAddresses']
            addresses = [item for sublist in rule_addr for item in sublist]
            orig_addrObj.extend(addresses)
            rule_fqdn = [v for k, v in rule.items() if k == 'destinationFqdns']
            fqdns = [item for sublist in rule_fqdn for item in sublist]
            orig_fqdn.extend(fqdns)
        if rule['ruleType'] == 'ApplicationRule':
            rule_fqdn = [v for k, v in rule.items() if k == 'targetFqdns']
            fqdns = [item for sublist in rule_fqdn for item in sublist]
            orig_fqdn.extend(fqdns)
            rule_url = [v for k, v in rule.items() if k == 'webCategories']
            urls = [item for sublist in rule_url for item in sublist]
            orig_url.extend(urls)

    servObj = list(set(orig_servObj))
    addrObj = list(set(orig_addrObj))
    addrObj = [x for x in addrObj if x != '*']
    fqdnObj = list(set(orig_fqdn))
    urlObj = list(set(orig_url))

    invalid_ips = []
    valid_ips = []
    invalid_fqdns = []
    valid_fqdns = []

    for each in addrObj:
        if validate_ip(each):
            valid_ips.append(each)
        else:
            invalid_ips.append(each)

    for each in fqdnObj:
        if resolve_dns(each):
            valid_fqdns.append(each)
        else:
            invalid_fqdns.append(each)
    
    #Export Azure firewall rules to an Excel file
    output_rules = []
    for each in rules:
        output_rules.append({k: ",".join(map(str, v)) if isinstance(v, list) else v for k, v in each.items()})
    
    with pd.ExcelWriter(cfgFile, engine='xlsxwriter') as writer:
        df_rules = pd.DataFrame(output_rules)
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
            'service_object': servObj
        })
        headers = df_obj2.columns.tolist()
        df_obj2.to_excel(writer, sheet_name='service_object', index=False, )
        workbook = writer.book
        worksheet3 = writer.sheets['service_object']
        worksheet3.autofit()
        df_obj3 = pd.DataFrame({
            'url_category': urlObj
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

    # Validate if the required objects are existing on Panorama
    s_addr = "$\\|".join(valid_ips+valid_fqdns)+"$"
    s_serv = "$\\|".join(servObj)+"$"
    s_rule = "$\\|".join([e['name'] for e in rules])
    extSERV = []
    extADDR = []
    extRule = []
    
    pano.connect()
    pano.show('set cli pager off', expect_string=r'>', delay_factor=4)
    pano.show('set cli config-output-format set', expect_string=r'>', delay_factor=4)
    pano.show('configure', expect_string=r'#', delay_factor=4)
    if s_serv:
        cmd = f"show shared service | match {s_serv}"
        srv_resp = pano.show(cmd, expect_string=r'#', delay_factor=4)
        for item in list(filter(None, srv_resp.split('\n'))):
            extSERV.extend(re.findall(r"service\s(\S+)\sprotocol\s(tcp|udp)\sport\s(\S+)", item))
    if s_addr:
        cmd = f"show shared address | match {s_addr}"
        addr_resp = pano.show(cmd, expect_string=r'#', delay_factor=4)
        for item in list(filter(None, addr_resp.split('\n'))):
            extADDR.extend(re.findall(r"\saddress\s(\S+)\s\S+\s(\S+)", item))
    if s_rule:
        cmd = f"show device-group {loc} post-rulebase security rules | match {s_rule}"
        rule_resp = pano.show(cmd, expect_string=r'#', delay_factor=4)
        for r in [e['name'] for e in rules]:
            if r in rule_resp:
                extRule.append(r)

    pano.show('exit', expect_string=r'>', delay_factor=4)
    pano.show('set cli config-output-format default', expect_string=r'>', delay_factor=4)
    pano.disconnect()

    #create pan-os set configurations
    if extRule:
        print(f"\n📌 Desired rulebases already existing on PAN:\n----------------------------------------------\n{'\n'.join(extRule)}")
    if extADDR or extSERV:
        print(f"\n📌 Desired objects already existing on PAN:\n----------------------------------------------\n{'\n'.join(extADDR+extSERV)}")

    req_rules = []
    for each in rules:
        if each['name'] not in extRule:
            r_rule = {k: v for k,v in each.items()}
            if r_rule['ruleType'] == 'NetworkRule':
                if "sourceAddresses" in r_rule.keys():
                    for i, a in enumerate(r_rule["sourceAddresses"]):
                        for (name, addr) in extADDR:
                            if addr == a:
                                r_rule["sourceAddresses"][i] = name
                if "destinationAddresses" in r_rule.keys():
                    for i, a in enumerate(r_rule["destinationAddresses"]):
                        for (name, addr) in extADDR:
                            if addr == a:
                                r_rule["destinationAddresses"][i] = name
                if "destinationPorts" in r_rule.keys():
                    for i, s in enumerate(r_rule["destinationPorts"]):
                        for (name, protocol, port) in extSERV:
                            if protocol in s and port in s:
                                r_rule["destinationPorts"][i] = name
            req_rules.append(r_rule)


if __name__ == "__main__":
    class PASSWORD(argparse.Action):
        def __call__(self, parser, namespace, values, option_string):
            if values is None:
                values = getpass.getpass()
            setattr(namespace, self.dest, values)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--u', help='Username', type=str,
    )
    parser.add_argument(
        '--p', help='Password', action=PASSWORD, nargs='?', dest='password', type=str
    )
    parser.add_argument(
        '--f', help='Configuration data file', type=str, required=True
    )
    parser.add_argument(
        '--l', help='Target Device Group', type=str, default='Shared'
    )
    args = parser.parse_args()

    if args.u:
        username = args.u
    else:
        username = os.getlogin()

    dataFile = args.f
    cfgFile = dataFile.split('.')[0]+'.xlsx'
    loc = args.l

    if os.path.exists(f"{dataFilePath}/{dataFile}"):
        if Path(f"{dataFilePath}/{dataFile}").suffix.lower() == '.json':
            with open(f"{dataFilePath}/{dataFile}", encoding="utf-8-sig") as f:
                data = json.load(f)
        else:
            print("❌ Error: Invalid file format!")
            sys.exit()
    else:
        print("❌ Error: File not exists!")
        sys.exit()
    
    pano = NetworkDevice(
        host = '192.168.10.254',
        username = 'admin',
        password = 'Jy@2108A1!',
        secret = 'secret',
        device_type = 'paloalto_panos'
    )
    
    createConfig(data, loc, pano, f"{cfgFilePath}/{cfgFile}")
