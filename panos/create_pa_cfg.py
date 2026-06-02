
import requests, xmltodict, argparse
import jinja2, re, ipaddress, socket, getpass, sys
import pandas as pd
from pathlib import Path
from colorama import init, Fore, Back, Style
from tabulate import tabulate
from colorama import just_fix_windows_console
from ipaddress import IPv4Address, IPv4Network
from netmiko import ConnectHandler
from netmiko import NetmikoTimeoutException
from netmiko import NetmikoAuthenticationException

init(autoreset=True)
just_fix_windows_console()

def connect(device):
    global net_connect
    try:
        net_connect = ConnectHandler(**device)
        prompter = net_connect.find_prompt()
        #if '>' in prompter:
            #net_connect.enable()
        return True
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as error:
        print(error)
        sys.exit(1)

def get_dns_name(ip_addr):
    try:
        hostname = socket.gethostbyaddr(ip_addr)[0].split(".")[0]
        return hostname
    except socket.herror:
        return "NXDOMAIN"

def getAPIKey(loginPAN):
    requests.packages.urllib3.disable_warnings()
    try:
        # get API key from Panorama
        baseURL = f"https://{loginPAN['host']}/api/"
        apiPath = f"{baseURL}?type=keygen&user={loginPAN['username']}&password={loginPAN['password']}"
        getKey = requests.request("GET", apiPath, verify=False)
        getKey.raise_for_status()
        getKeyDict = xmltodict.parse(getKey.content)
        apiKey = getKeyDict['response']['result']['key']
        return apiKey
    except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError, requests.exceptions.Timeout) as error:
        print(f"{Fore.YELLOW}{error}")
        sys.exit(1)

def createConfig(basePath, loc, rules, req_addr, req_srv, config, description):
    tPath = f"{basePath}/templates"
    loader = jinja2.FileSystemLoader(searchpath=tPath)
    env = jinja2.Environment(autoescape=True, loader=loader)
    if loc == 'evr':
        address_template = env.get_template('P_pan_address_template_txt.j2')
        service_template = env.get_template('P_pan_service_template_txt.j2')
        rule_template = env.get_template('P_evr_pan_rule_template_txt.j2')
    elif loc == 'teck':
        address_template = env.get_template('P_pan_address_template_txt.j2')
        service_template = env.get_template('P_pan_service_template_txt.j2')
        rule_template = env.get_template('P_teck_pan_rule_template_txt.j2')

    # Generate address object configurations
    if req_addr:
        addresses = []
        networks = []
        fqdns = []
        for obj in req_addr:
            if '/' in obj and '.' in obj:
                try:
                    net = IPv4Network(obj).exploded
                except ipaddress.AddressValueError as e:
                    fqdns.append(obj)
                else:
                    networks.append(net)
            elif obj != 'any':
                try:
                    host = IPv4Address(obj).exploded
                    hostname = get_dns_name(obj)
                except ipaddress.AddressValueError as e:
                    fqdns.append(obj)
                else:
                    addresses.extend([(host,hostname)])
        items = {'addresses': addresses, 'networks': networks, 'fqdns': fqdns}
        addr_cfg = address_template.render(items)
        addr_cfg = "".join([s for s in addr_cfg.splitlines(True) if (not re.search(r"^\s*$", s))])
        addrFile = f"{basePath}/config_files/{loc} config/Address_{loc}_{config.replace('csv','txt')}"   
        with open(addrFile, 'w') as f:
            f.write('+--------------------- Required Address Objects ---------------------+\n')
            f.write(addr_cfg)
        print(f"\n+--------------------- {Fore.YELLOW}Required Address Objects{Fore.RESET} ---------------------+")
        print(f"{Fore.WHITE}{addr_cfg}")
    else:
        addr_cfg = ''
    # Generate service object configurations
    if req_srv:
        srv_cfg = service_template.render({'req_srv': req_srv})
        srv_cfg = "".join([s for s in srv_cfg.splitlines(True) if (not re.search(r"^\s*$", s))])
        srvFile = f"{basePath}/config_files/{loc} config/Service_{loc}_{config.replace('csv','txt')}"
        with open(srvFile, 'w') as f:
            f.write('+--------------------- Required Service Objects ---------------------+\n')
            f.write(srv_cfg)
        print(f"\n+--------------------- {Fore.YELLOW}Required Service Objects{Fore.RESET} ---------------------+")
        print(f"{Fore.WHITE}{srv_cfg}")
    else:
        srv_cfg = ''
    # Generate rule configurations
    new_addr = []
    for item in list(filter(None, addr_cfg.split('\n'))):
        new_addr.extend(re.findall(r"address\s(\S+)\s\S+\s(\S+)", item))
    new_srv = []
    for item in list(filter(None, srv_cfg.split('\n'))):
        new_srv.extend(re.findall(r"service\s(\S+)\sprotocol\s(tcp|udp)\sport\s(\d{1,5})", item))
    rule_cfg = ''
    #print(('\n').join(new_addr))
    #print(('\n').joinnew_srv))
    for rule in rules:
        for i, a in enumerate(rules[rule]["SourceIP"]):
            for (name, addr) in new_addr:
                if addr == a:
                    rules[rule]["SourceIP"][i] = name
        for i, a in enumerate(rules[rule]["DestinationIP"]):
            for (name, addr) in new_addr:
                if addr == a:
                    rules[rule]["DestinationIP"][i] = name
        for i, s in enumerate(rules[rule]["Service"]):
            for (name, protocol, port) in new_srv:
                if protocol in s and port in s:
                    rules[rule]["Service"][i] = name
        rules[rule]["SourceIP"] = ','.join(rules[rule]["SourceIP"])
        rules[rule]["SourceUser"] = ','.join(rules[rule]["SourceUser"])
        rules[rule]["DestinationIP"] = ','.join(rules[rule]["DestinationIP"])
        rules[rule]["Application"] = ','.join(rules[rule]["Application"])
        rules[rule]["Service"] = ','.join(rules[rule]["Service"])
        rules[rule]["description"] = description
        rule_cfg += rule_template.render(rules[rule])
    rule_cfg = "".join([s for s in rule_cfg.splitlines(True) if (not re.search(r"^\s*$", s))])
    ruleFile = f"{basePath}/config_files/{loc} config/Rule_{loc}_{config.replace('csv','txt')}"
    with open(ruleFile, 'w') as f:
        f.write('+------------------------ Rulebases ------------------------+\n')
        f.write(rule_cfg)
    #print(Fore.WHITE+rule_cfg)
        
def runner():
    class DEVICE(object):
        def __init__(self, host='', username='', password='', device_type=''):
            self.host = host
            self.username = username
            self.password = password
            self.device_type = device_type
    class Password(argparse.Action):
        def __call__(self, parser, namespace, values, option_string):
            if values is None:
                values = getpass.getpass()

            setattr(namespace, self.dest, values)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--u', help='Username', type=str,
    )
    parser.add_argument(
        '--p', help='Password', action=Password, nargs='?', dest='password', type=str
    )
    parser.add_argument(
        '--c', help='CSV Configuration file name', type=str, required=True
    )
    parser.add_argument(
        '--d', help='Task/Change ticket number for description ', type=str, required=True
    )
    parser.add_argument(
        '--evr', help='CGC-CFW at EVR data center', action='store_true'
    )
    parser.add_argument(
        '--teck', help='CGY-CFW at TECK data center', action='store_true'
    )
    args = parser.parse_args()
    config = args.c
    description = args.d

    basePath = Path.home() / 'Desktop' / 'pan_config'
    if args.evr:
        dev = DEVICE('10.77.99.11', args.u, args.password, 'paloalto_panos')
        loc = 'evr'
    elif args.teck:
        dev = DEVICE('172.31.45.100', args.u, args.password, 'paloalto_panos')
        loc = 'teck'
    loginPAN = {
        'host': dev.host,
        'username': dev.username,
        'password': dev.password,
        'device_type': dev.device_type
    }
    # Get configuration data for desired security rules
    inFile = f"{basePath}/config_data/{config}"
    df = pd.read_csv(
        inFile,
        header=0,
        #keep_default_na=False,
        #index_col=['RuleName'],
        usecols=['RuleName', 'SourceZone', 'SourceUser', 'SourceIP', 'DestinationZone', 'DestinationIP', 'Application', 'Service', 'Action']
    )
    # Detect and remove row with index of None or NaN
    #df = df[df.index.notna()]
    #df = df[df.index.notnull()]
    # Remove row with empty 'RuleName'
    df.dropna(subset=['RuleName'], inplace=True)
    # Replace empty cells with string ''
    df.fillna('', inplace=True)
    print(df)
    desired_rules = {}
    for i in df.index:
        desired_rules.update({df.loc[i]['RuleName']: {}})
    for i in df.index:
        name = df.loc[i]['RuleName'].strip(' ')
        srcZone = df.loc[i]['SourceZone'].strip(' ')
        srcIP = df.loc[i]['SourceIP'].strip(' ')
        srcUser = df.loc[i]['SourceUser'].strip(' ')
        destZone = df.loc[i]['DestinationZone'].strip(' ')
        destIP = df.loc[i]['DestinationIP'].strip(' ')
        app = df.loc[i]['Application'].strip(' ')
        service = df.loc[i]['Service'].strip(' ')
        action = df.loc[i]['Action'].strip(' ')
        if desired_rules[name]:
            desired_rules[name]['SourceIP'].extend(srcIP.split(','))
            desired_rules[name]['SourceUser'].extend(srcUser.split(','))
            desired_rules[name]['DestinationIP'].extend(destIP.split(','))
            desired_rules[name]['Application'].extend(app.split(','))
            desired_rules[name]['Service'].extend(service.split(','))
        else:
            desired_rules[name] = {
                 'RuleName': name,
                 'SourceZone': srcZone,
                 'SourceIP': srcIP.split(','),
                 'SourceUser': srcUser.split(','),
                 'DestinationZone': destZone,
                 'DestinationIP': destIP.split(','),
                 'Application': app.split(','),
                 'Service': service.split(','),
                 'Action': action
            }

    addresses = []
    services =[]
    for rule in desired_rules:
        desired_rules[rule]['SourceIP']=list(filter(None, sorted(set(desired_rules[rule]['SourceIP']))))
        desired_rules[rule]['SourceUser']=list(filter(None, sorted(set(desired_rules[rule]['SourceUser']))))
        desired_rules[rule]['DestinationIP']=list(filter(None, sorted(set(desired_rules[rule]['DestinationIP']))))
        desired_rules[rule]['Application']=list(filter(None, sorted(set(desired_rules[rule]['Application']))))
        desired_rules[rule]['Service']=list(filter(None, sorted(set(desired_rules[rule]['Service']))))
        addresses.extend(desired_rules[rule]['SourceIP'])
        addresses.extend(desired_rules[rule]['DestinationIP'])
        services.extend(desired_rules[rule]['Service'])
    addresses = sorted(set(addresses))
    services = sorted(set(services))
    rList = desired_rules.keys()
    if 'any' in addresses:
        addresses.remove('any')
    if ' ' in addresses:
        addresses.remove(' ')
    if 'any' in services:
        services.remove('any')
    if ' ' in services:
        services.remove(' ')
    if 'application-default' in services:
        services.remove('application-default')

    print(f"\n{Fore.WHITE}All referenced objects in the rules:\n--------------------------------------")
    for each in addresses+services:
        print(each)
    #print(json.dumps(desired_rules,indent=2))
    #srv_obj = re.findall(r"(\d{2,5}|^\w+$)", ('\n').join(services), flags=re.M)
    
    # Validate if the required objects are existing on Panorama
    srv = ('$\\|').join(services).replace('p-', 'p.*\\s')+'$'
    addr = ('$\\|').join(addresses)+'$'
    dRules = ('\\|').join(rList)
    if connect(loginPAN):
        print(f"\nConnecting to {loginPAN['host']} and validating objects......")
        net_connect.send_command('set cli pager off', expect_string=r'>', delay_factor=4)
        net_connect.send_command('set cli config-output-format set', expect_string=r'>', delay_factor=4)
        net_connect.send_command('configure', expect_string=r'#', delay_factor=4)
        ext_srv = []
        ext_addr = []
        ext_rule = []
        if services:
            cmd = f"show shared service | match {srv}"
            srv_resp = net_connect.send_command(cmd, expect_string=r'#', delay_factor=4)
            for item in list(filter(None, srv_resp.split('\n'))):
                ext_srv.extend(re.findall(r"service\s(\S+)\sprotocol\s(tcp|udp)\sport\s(\S+)", item))
        if addresses:
            cmd = f"show shared address | match {addr}"
            addr_resp = net_connect.send_command(cmd, expect_string=r'#', delay_factor=4)
            for item in list(filter(None, addr_resp.split('\n'))):
                ext_addr.extend(re.findall(r"address\s(\S+)\s\S+\s(\S+)", item))
        if rList:
            if loc == 'evr':
                cmd = f"show device-group CORE pre-rulebase security rules | match {dRules}"
            elif loc == 'teck':
                cmd = f"show device-group Core pre-rulebase security rules | match {dRules}"
            rule_resp = net_connect.send_command(cmd, expect_string=r'#', delay_factor=4)
            for r in rList:
                if r in rule_resp:
                    ext_rule.append(r)
            ext_rule = sorted(set(ext_rule))

        net_connect.send_command('exit', expect_string=r'>', delay_factor=4)
        net_connect.send_command('set cli config-output-format default', expect_string=r'>', delay_factor=4)
        net_connect.disconnect()
        
        # Update the configuration data of desired rules with the existing objects
        if ext_rule:
            print(f"\n{Fore.YELLOW}Desired rulebases existing on PAN:\n--------------------------------------")
            for r in ext_rule:
                print(r)

        req_rules = {}
        for rule in desired_rules:
            for i, a in enumerate(desired_rules[rule]["SourceIP"]):
                for (name, addr) in ext_addr:
                    if addr == a:
                        desired_rules[rule]["SourceIP"][i] = name
            for i, a in enumerate(desired_rules[rule]["DestinationIP"]):
                for (name, addr) in ext_addr:
                    if addr == a:
                        desired_rules[rule]["DestinationIP"][i] = name
            for i, s in enumerate(desired_rules[rule]["Service"]):
                for (name, protocol, port) in ext_srv:
                    if protocol in s and port in s:
                        desired_rules[rule]["Service"][i] = name
            if rule not in ext_rule:
                req_rules.update({rule: desired_rules[rule]})
        if req_rules:
            req_addr = []
            req_srv = []
            for rule in req_rules:
                for i, a in enumerate(req_rules[rule]["SourceIP"]):
                    if all(a not in obj for obj in addr_resp.split('\n')):
                        req_addr.append(req_rules[rule]["SourceIP"][i])
                for i, a in enumerate(req_rules[rule]["DestinationIP"]):
                    if all(a not in obj for obj in addr_resp.split('\n')):
                        req_addr.append(req_rules[rule]["DestinationIP"][i])
                for i, s in enumerate(req_rules[rule]["Service"]):
                    if '-' in s:
                        if all((s.split('-')[0] not in obj or s.split('-')[1] not in obj) for obj in srv_resp.split('\n')):
                            req_srv.append(req_rules[rule]["Service"][i])
            req_addr = sorted(set(req_addr))
            req_srv = sorted(set(req_srv))
            #print(json.dumps(req_rules, indent=2))
            print(f"\n{Fore.WHITE}The existing configurations for objects:\n-----------------------------------------")
            for each in ext_addr+ext_srv:
                print(each)   
            createConfig(basePath, loc, req_rules, req_addr, req_srv, config, description)
        print(f"\n{Fore.WHITE}Task completed!")
    else:
        print(f"{Fore.YELLOW}Failed to validate required objects on Panorama, and abort tasks!")

if __name__ == "__main__":
    runner()
