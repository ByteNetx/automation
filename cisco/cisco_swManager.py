
import os
import sys
import logging
import json
import yaml
from datetime import datetime
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from concurrent.futures import ThreadPoolExecutor, as_completed
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

class CiscoSwitchManager:
    def __init__(self, username: str, password: str, cfgData: Dict):

        self.username = username
        self.password = password
        self.cfgData = cfgData
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

    def update_config(self, commands: List):
            """
            Apply configuration updates to the switch
                
            Returns:
                Boolean indicating success or failure
            """

            try:

                if commands and self.connection:
                    output = self.connection.send_config_set(commands)

                    logger.info(f"Updated configuration on {self.dev_name}-({self.host}):\n{output}")

                    # Save configuration
                    self.save_config()

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
                output = self.connection.send_command('copy running-config startup-config', read_timeout=30)
                logger.info(f"Save configuration on {self.dev_name}-({self.host}):\n{output}")
            elif self.device_type == 'cisco_ios' and self.connection:
                # IOS-XE: write memory
                output = self.connection.send_command('write memory', expect_string=r'#')
                logger.info(f"Save configuration on {self.dev_name}-({self.host}):\n{output}")
                
            return True
            
        except Exception as e:
            logger.error(f"Failed to save configuration on {self.host}: {e}")
            return False

    def show_config(self, commands):
        try:
            output = ''
            if commands and self.connection:
                for cmd in commands:
                    output += self.connection.send_command(cmd)
    
                return output
            else:
                return None

        except Exception as e:
            logger.info(f"Configuration not exist on {self.host}: {e}")
            return None

    def disconnection(self):
            if self.connection:
                self.connection.disconnect()

    def switch_operation(self):

        results = {}

        for dev_type, dev_data in self.cfgData.items():
            device_type = DeviceType.from_string(dev_type).value
            op_commands = dev_data.get('op_commands', [])
            cfg_commands = dev_data.get('cfg_commands', [])
            switches = dev_data.get('switches', [])
            display = {}

            if any(c for c in [op_commands, cfg_commands]) and switches:
                for host in switches:
                    
                    if self.connect(host, device_type):
                        if op_commands:
                            output = self.show_config(op_commands)
                            display[f"{self.dev_name}-({self.host})"] = output
                        if cfg_commands:
                            if self.update_config(cfg_commands):
                                results[f"{self.dev_name}-({self.host})"] = "success"

                        self.disconnection()
        if display:
            for key, value in display.items():
                logger.info("=" * 30)
                logger.info(key)
                logger.info("=" * 30)
                logger.info(value)
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

    if not PASSWORD:
        credentails = get_secret(VAULT, vaultpath)
        PASSWORD = credentails.get(USERNAME)

    manager = CiscoSwitchManager(USERNAME, PASSWORD, data)
    results = manager.switch_operation()

    if results:
        logger.info("Operation results:")
        for obj, success in results.items():
            status = "✓" if success == "success" else "✗"
            logger.info(f"{status} {obj}")


if __name__ == "__main__":
    runner()
