
import os
import sys
import logging
import re
import yaml
from datetime import datetime
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from enum import Enum
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass, asdict


basePath = Path.home() / 'pyenv3.9' / 'cisco' / 'cisco_project'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'{basePath}/logs/config_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class OpType(Enum):
    """Supported operation mode"""
    show = "show"
    update = "update"
    @classmethod
    def from_string(cls, value: str) -> 'OpType':
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(f"Invalid category: {value}. Must be either 'show' or 'update'")
        
class DeviceType(Enum):
    """Supported switch types"""
    NEXUS = "cisco_nxos"
    IOS = "cisco_ios"
    @classmethod
    def from_string(cls, value: str) -> 'DeviceType':
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(f"Invalid switch type: {value}. Must be either 'cisco_nxos' or 'cisco_ios'")

class CiscoAdminManager:
    def __init__(self, username: str, password: str, cfgData: Dict, credentials: Dict):

        self.username = username
        self.password = password
        self.cfgData = cfgData
        self.credentials = credentials
        self.host = None
        self.device_type = None
        self.dev_name = None
        self.connection = None


    def connect(self, host: str=None, device_type: str=None):
        try:
            switch_params = {
                'device_type': device_type,
                'host': host,
                'username': self.username,
                'password': self.password,
                'global_delay_factor': 2,
                'verbose': False
            }

            self.connection = ConnectHandler(**switch_params)
            prompt = self.connection.find_prompt()
            self.dev_name = prompt.strip("#")
            self.device_type = device_type
            self.host = host
            logger.info(f"Successfully connect to {self.host} ({self.dev_name})")

            return True
            
        except NetmikoAuthenticationException as e:
            logger.error(f"Authentication failed for {host}: {e}")
            return False
        except NetmikoTimeoutException as e:
            logger.error(f"Connection timeout for {host}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error connecting to {host}: {e}")
            return False

    def update_admin(self, commands: List):

            try:
                if commands and self.connection:
                    output = self.connection.send_config_set(commands)

                    logger.info(f"Updated local admin on {self.dev_name}-({self.host}):{output}")

                    return True
                else:
                    return False
                
            except Exception as e:
                logger.error(f"Failed to apply configuration to {self.host}: {e}")
                return False


    def save_config(self):

        try:
            if  self.device_type == 'cisco_nxos' and self.connection:
                # Nexus: copy running-config startup-config
                if self.connection.send_command('copy running-config startup-config', read_timeout=30):
                    logger.info(f"Saved configuration on {self.dev_name} ({self.host})")
            elif self.device_type == 'cisco_ios' and self.connection:
                # IOS-XE: write memory
                if  self.connection.send_command('write memory', expect_string=r'#'):
                    logger.info(f"Saved configuration on {self.dev_name} ({self.host})")
                
            return True
            
        except Exception as e:
            logger.error(f"Failed to save configuration on {self.host}: {e}")
            return False

    def remove_user(self, commands: List):
            try:
                if commands and self.connection:
                
                    output = self.connection.send_multiline_timing(commands)
                    logger.info(f"Removed local admin on {self.dev_name}-({self.host}):{output}")
        
                    return True
                else:
                    return False
    
            except:
                logger.info(f"Failed to remove the local admin on {self.dev_name}-({self.host})")
                return False


    def show_config(self, commands: List):
        try:
            if commands and self.connection:
                output = ''
                for cmd in commands:
                    output += self.connection.send_command(cmd)
    
                return output
            else:
                return None

        except:
            return None

    def disconnection(self):
            if self.connection:
                if self.connection.disconnect():
                    return True

    def admin_operation(self, operation: str='show'):

        results = {}
        non_compliants = {}
        compliants = {}
        missing = {}
        failed_connect = []
                
        for category, cfg_data in self.cfgData.items():
            new_admin = cfg_data.get('new_admin', None)
            new_passwd = self.credentials.get(new_admin, None)
            new_enable = self.credentials.get(f"{new_admin}-enable", None)
            devices = {k: v for k, v in cfg_data.items() if k != 'new_admin'}
            cisco_ios_updates = [
                f"username {new_admin} secret {new_passwd}",
                f"enable secret {new_enable}"
            ]
            cisco_nxos_updates = [
                f"username {new_admin} password {new_passwd} role network-admin"
            ]

            if OpType.from_string(operation).value == 'update':
                if all(v is not None for v in [new_admin, new_passwd, new_enable]) and devices:
                    for dev_type, switches in devices.items():
                        device_type = DeviceType.from_string(dev_type).value
                        if device_type == 'cisco_ios':
                            updates= cisco_ios_updates
                        elif device_type == 'cisco_nxos':
                            updates= cisco_nxos_updates
                        for host in switches:
                            removing_users = ["config term"]
                            
                            if self.connect(host, device_type):
                                pre_output = self.show_config(["show run | inc username"])
                                pre_compliant_data = re.findall(r"username\s((\S+)(?:.+secret\s9)|(\S+)(?:.+password\s9))", pre_output)
                                pre_noncompliant_data = re.findall(r"username\s((\S+)(?:.+secret\s[0,5,6,7,8])|(\S+)(?:.+password\s[0,5,6,7,8]))", pre_output)
                                
                                pre_compliant = [ item for tup in pre_compliant_data for item in tup if item != '' and ' ' not in item]
                                pre_noncompliant = [ item for tup in pre_noncompliant_data for item in tup if item != '' and ' ' not in item]

                                
                                if new_admin in pre_compliant and not pre_noncompliant:
                                    logger.info(f"{self.dev_name}_({self.host}) already compliant")
                                else:
                                    if new_admin in pre_noncompliant:
                                        self.remove_user(["config term", f"no username {new_admin}", "\n", "end"])

                                    if self.update_admin(updates):
                                        post_output = self.show_config(["show run | inc username"])
                                        current_users = re.findall(r"username\s(\S+)", post_output)
                                        old_users = [u for u in current_users if u != new_admin]
    
                                        if new_admin in current_users and not old_users:
                                            results[f"{self.dev_name}_({self.host})"] = "success"
                                        elif new_admin in current_users and old_users:
                                            for user in old_users:
                                                removing_users.extend([f"no username {user}", "\n"])

                                            removing_users.append("end")
                                            if self.remove_user(removing_users):
    
                                                    results[f"{self.dev_name}_({self.host})"] = "success"
                                        else:
                                            results[f"{self.dev_name}_({self.host})"] = "fail"

                                    # Save configuration
                                    self.save_config()

                                if self.disconnection():
                                    logger.info(f"Logged out {self.dev_name}_({self.host})")

                            else:
                                failed_connect.append(host)


            elif OpType.from_string(operation).value == 'show':
                if devices:
                    for dev_type, switches in devices.items():
                        device_type = DeviceType.from_string(dev_type).value

                        for host in switches:
                            
                            if self.connect(host, device_type):
                                output = self.show_config(["show run | inc username"])
                                compliant_data = re.findall(r"username\s((\S+)(?:.+secret\s9)|(\S+)(?:.+password\s9))", output)
                                noncompliant_data = re.findall(r"username\s((\S+)(?:.+secret\s[0,5,6,7,8])|(\S+)(?:.+password\s[0,5,6,7,8]))", output)
                               
                                compliant = [ item for tup in compliant_data for item in tup if item != '' and ' ' not in item]
                                noncompliant = [ item for tup in noncompliant_data for item in tup if item != '' and ' ' not in item]

                                if noncompliant:
                                    non_compliants[f"{self.dev_name}-({self.host})"] = ' '.join(noncompliant)
                                if new_admin in compliant and not noncompliant:
                                    compliants[f"{self.dev_name}-({self.host})"] = "pass"
                                if new_admin not in compliant and not noncompliant:
                                    missing[f"{self.dev_name}-({self.host})"] = new_admin


                                self.disconnection()

                            else:
                                failed_connect.append(host)

        if failed_connect:
            logger.info("FAILED CONNECTING TO SWITCHES:")
            logger.info("=" * 50)
            for each in failed_connect:
                logger.info(f"✗ {each}")

        if OpType.from_string(operation).value == 'show':
            if non_compliants:
                logger.info("NON-COMPLIANT SWITCHES:")
                logger.info("=" * 50)
                for dev, users in non_compliants.items():
                    logger.info(f"❌ {dev}: {users}")

            if missing:
                logger.info("SWITCH MISSING REQUIRED USERS:")
                logger.info("=" * 50)
                for dev, user in missing.items():
                    logger.info(f"❌ {dev}: missing user {user}")
    
            if compliants:
                logger.info("COMPLIANT SWITCHES:")
                logger.info("=" * 50)
                for dev, status in compliants.items():
                    logger.info(f"✅ {dev}: {status}")

        return results

def parse_arguments():
    import getpass
    import argparse
    """Parse command line arguments."""
    class Password(argparse.Action):
        def __call__(self, parser, namespace, values, option_string):
            if values is None:
                values = getpass.getpass()
            setattr(namespace, self.dest, values)

    parser = argparse.ArgumentParser(
        description="Create/delete/list objects in Panorama Device Groups"
    )
    
    # Common arguments
    parser.add_argument("--username", "-u", type=str, required=True,
                        help="Cisco admin username")
    parser.add_argument(
            "--password", "-p", type=str,
            help='Cisco admin password', action=Password, nargs='?', dest='passwd'
        )
    parser.add_argument("--file", "-f", type=str, required=True,
                        help="Configuration YAML file")
    parser.add_argument("--operation", "-o", choices=['show', 'update'], 
                            nargs="?", const="show", default='show',
                           help="Operation commands to show/update configuration on Cisco switches. Default to 'show'")

    return parser.parse_args()

def get_secret(vault, vaultpath):
    from encryption import CredentialManager
    try:
        manager = CredentialManager(vault, vaultpath)
        credentails = manager.decrypt()
        return credentails
    except:
        return False

def runner():
    args = parse_arguments()

    USERNAME = args.username
    PASSWORD = args.passwd
    OPERATION = args.operation
    VAULT = "cisco_secrets.bin"
    vaultpath = Path.home() / 'pyenv3.9' / 'secrets'

    cfgFile = f"{basePath}/config/{args.file}"
        
    if os.path.isfile(cfgFile):
        try:
            with open(cfgFile, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to open file {args.file}: {e}")
            sys.exit()
    else:
        logger.error(f"The file {cfgFile} does not exist")
        sys.exit()

    credentails = get_secret(VAULT, vaultpath)

    if not credentails:
        logger.error(f"Failed to get credentials from vault")
        sys.exit()

    if not PASSWORD:
        PASSWORD = credentails.get(USERNAME)
    
    manager = CiscoAdminManager(USERNAME, PASSWORD, data, credentails)

    results = manager.admin_operation(OPERATION)

    if results:
        logger.info("Operation results:")
        for obj, success in results.items():
            status = "✓" if success == "success" else "✗"
            logger.info(f"{status} {obj}")

    logger.info("Successfully run the script")

if __name__ == "__main__":
    runner()
