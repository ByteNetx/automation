import argparse, getpass, datetime, re, os
import yaml, jinja2, sys
from cryptography.fernet import Fernet
from pathlib import Path
from colorama import Fore, Back, Style, init
from netmiko import ConnectHandler
from netmiko import NetmikoTimeoutException
from netmiko import NetmikoAuthenticationException

init(autoreset=True)

def banner():
    print(Fore.YELLOW+"""
#-----------------------------------------------------------------#
#  The script rotates locally configured admin accounts & enable  #
#  secrets on Cisco devices. After succussfully running the       #
#  script, please verify configuration changes by checking the    #
#  change logs in the following location:                         # 
#    ~/pyenv3.9/cisco/logs/                                       #
#                                                                 #
#  Important:                                                     #
#    Remove the change log file after validation, since it        #
#    contains admin password and enable secret in plain text!     #
#-----------------------------------------------------------------#
""")
    
def connect(device,logwriter):
    global ssh_connect
    try:
        ssh_connect = ConnectHandler(**device)
        prompter = ssh_connect.find_prompt()
        if '>' in prompter:
            ssh_connect.enable()
        return True
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as error:
        print(error)
        logwriter.write(f"An error to SSH to {device['host']}\n{error}\n")
        pass

def runner():
    class DEVICE(object):
        def __init__(self, host='', username='', password='', secret='', device_type=''):
            self.host = host
            self.username = username
            self.password = password
            self.secret = secret
            self.device_type = device_type

    class PASSWORD(argparse.Action):
        def __call__(self, parser, namespace, values, option_string):
            if values is None:
                values = getpass.getpass()
                setattr(namespace, self.dest, values)

    banner()

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--u', help='Username', type=str,
    )
    parser.add_argument(
        '--p', help='Password', action=PASSWORD, nargs='?', dest='password', type=str, required=True
    )
    parser.add_argument(
        '--f', help='Device YAML file', type=str, required=True
    )
    args = parser.parse_args()

    if args.u:
        username = args.u
    else:
        username = os.getlogin()

    basePath = Path.home() / 'netdev' / 'python-env' / 'cisco'
    devFile = f"{basePath}/data/{args.f}"

    with open(devFile, 'r') as f:
        data = yaml.safe_load(f)

    devData = data['devices']
    cfgData = data['cfg-data']
    devices = {devType: devList for devType, devList in devData.items() if devList is not None}
    if any(Value is None for Key, Value in cfgData.items()):
        err = f"Missing the required configuration parameters in the following device file!\n{devFile}"
        sys.exit(err)
    
    credFile = f"{basePath}/data/{data['credFile']}"

    with open(credFile, "rb") as f:
        encrypted_credentials= f.read()
    
    myKey = input(Fore.GREEN+"Enter decryption key:"+Fore.RESET)
    f  = Fernet(myKey)
    credentials = f.decrypt(encrypted_credentials).decode()
    cfgData.update({
        'new_passwd': credentials.split()[0].strip(),
        'new_enable': credentials.split()[1].strip()
    })
    
    templatePath = f"{basePath}/templates"
    loader = jinja2.FileSystemLoader(searchpath=templatePath)
    env = jinja2.Environment(autoescape=False, loader=loader)
    cisco_template = env.get_template(cfgData['template'])

    datenow = datetime.datetime.now().strftime("%Y%m%d")
    logFile = f"{basePath}/logs/change_logs_{datenow}.txt"
    logwriter = open(logFile, 'a')

    for devType, devList in devices.items():
        for each in devList:
            cfg_data = {}
            if each is not None:
                dev = DEVICE(each, username, args.password, args.password, devType)
                device = {
                    'host': dev.host,
                    'username': dev.username,
                    'password': dev.password,
                    'secret': dev.secret,
                    'device_type': dev.device_type
                }
                cfg_data.update({'dev_type': devType})
                cfg_data.update(cfgData)
                cis_cfg = cisco_template.render(cfg_data)
                cis_cfg = "".join([s for s in cis_cfg.splitlines(True) if (not re.search(r"^\s*$", s))])
                if connect(device,logwriter):
                    current_prompt = ssh_connect.find_prompt()
                    devName = current_prompt.strip("#")
                    print(f"\nConnected to {device['host']}-{devName} to deploy configurations")
                    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
                    logwriter.write(f"+++++++++++++++ {timestamp}-{device['host']}-{devName} +++++++++++++++\n")
                    
                    deploy_cfg = ssh_connect.send_config_set(cis_cfg.split('\n'))
        
                    showUser = ssh_connect.send_command('show run | i username')
                    output = re.findall(r"username\s(\S+)\s",showUser)
                    if output:
                        for user in cfg_data['current_admin']:
                            if user in output:
                                deploy_cfg += ssh_connect.send_multiline_timing(
                                    ["conf term",f"no username {user}","\n","end"]
                                )
    
                    if devType == "cisco_ios":
                        save_cfg = ssh_connect.save_config()
                    elif devType == "cisco_nxos":
                        save_cfg = ssh_connect.send_multiline_timing(
                            ["copy running-config startup-config","\n"]
                        )
                    logwriter.write(f"{showUser}\n\n{deploy_cfg}\n\n{save_cfg}\n\n")
                    ssh_connect.disconnect()
    
    logwriter.close()
    print('Task completed!')
if __name__ == "__main__":
    runner()
