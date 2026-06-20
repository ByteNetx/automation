#!/usr/bin/env python3
"""
Cisco Switch Configuration Update Script
Supports both IOS-XE and Nexus switches
Version: 1.0
"""

import argparse
import os
import sys
import logging
import json
from datetime import datetime
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from concurrent.futures import ThreadPoolExecutor, as_completed
import yaml
from encryption import CredentialManager
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'switch_update_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

basePath = Path.home() / 'pyenv3.13' / 'cisco'
username = os.getlogin().split('@')[0]
manager = CredentialManager("secrets.bin")
credentials = manager.decrypt()

try:
    password = credentials[username]
except:
    password = input(f"Enter the password of user \"{username}\" :")

class CiscoSwitchDeployer:
    def __init__(self, config_file='switches.yaml'):
        """
        Initialize the switch deployer with configuration file
        
        Args:
            config_file: YAML file containing switch information and configuration
        """
        self.config_file = config_file
        self.switches = []
        self.config_commands = {}
        self.results = {}
        
    def load_configuration(self):
        """
        Load switch configuration from YAML file
        """
        try:
            with open(self.config_file, 'r') as f:
                config = yaml.safe_load(f)
                
            self.switches = config.get('switches', [])
            self.config_commands = config.get('config_commands', {}) 
            logger.info(f"Loaded {len(self.switches)} switches")
            return True
            
        except FileNotFoundError:
            logger.error(f"Configuration file {self.config_file} not found")
            return False
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML file: {e}")
            return False
            
    def connect_to_device(self, switch_info):
        """
        Establish SSH connection to the switch
       
        """
        try:
            # Determine device type
            if 'nexus' in switch_info.get('platform', '').lower():
                device_type = 'cisco_nxos'
            else:
                device_type = 'cisco_ios'
                
            connection_params = {
                'device_type': device_type,
                'host': switch_info['host'],
                'username': username,
                'password': password,
                'timeout': 60,
                'session_timeout': 120,
                'global_delay_factor': 2,
                'verbose': False
            }
                
            logger.info(f"Connecting to {switch_info['host']} ({switch_info.get('name', 'Unknown')})")
            connection = ConnectHandler(**connection_params)

            return connection
            
        except NetmikoAuthenticationException as e:
            logger.error(f"Authentication failed for {switch_info['host']}: {e}")
            return None
        except NetmikoTimeoutException as e:
            logger.error(f"Connection timeout for {switch_info['host']}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error connecting to {switch_info['host']}: {e}")
            return None
            
    def backup_configuration(self, connection, switch_name):
        """
        Backup current running configuration
        
        Args:
            connection: Netmiko connection object
            switch_name: Name of the switch
            
        Returns:
            String containing the configuration or None if backup fails
        """
        try:
            logger.info(f"Backing up configuration for {switch_name}")
            
            # Show running config
            if 'nexus' in connection.device_type:
                output = connection.send_command('show running-config', expect_string=r'#')
            else:
                output = connection.send_command('show running-config', expect_string=r'#')
                
            # Save backup to file
            backup_dir = 'backups'
            os.makedirs(backup_dir, exist_ok=True)
            backup_file = f"{backup_dir}/{switch_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.cfg"
            
            with open(backup_file, 'w') as f:
                f.write(output)
                
            logger.info(f"Backup saved to {backup_file}")
            return output
            
        except Exception as e:
            logger.error(f"Failed to backup configuration for {switch_name}: {e}")
            return None
            
    def update_configuration(self, connection, switch_info, commands):
        """
        Apply configuration updates to the switch
        
        Args:
            switch_info: Dictionary containing switch information
            commands: List of configuration commands to apply
            
        Returns:
            Boolean indicating success or failure
        """
        try:
            switch_name = switch_info.get('name', switch_info['host'])
            logger.info(f"Applying configuration to {switch_name}")
            
            # Check if we need to use config mode
            if 'nexus' in connection.device_type:
                # Nexus switches
                output = connection.send_config_set(commands['nexus'], cmd_verify=False)
            else:
                # IOS-XE switches
                output = connection.send_config_set(commands['ios-xe'], cmd_verify=False)
                
            logger.info(f"Configuration applied successfully to {switch_name}")
            logger.debug(f"Output: {output}")
            
            # Save configuration
            if self.save_configuration(connection, switch_info):
                logger.info(f"Configuration saved on {switch_name}")
            else:
                logger.warning(f"Failed to save configuration on {switch_name}")
                
            return True
            
        except Exception as e:
            logger.error(f"Failed to apply configuration to {switch_info.get('name', switch_info['host'])}: {e}")
            return False
            
    def save_configuration(self, connection, switch_info):
        """
        Save running configuration to startup
        
        Args:
            connection: Netmiko connection object
            switch_info: Dictionary containing switch information
            
        Returns:
            Boolean indicating success or failure
        """
        try:
            if 'nexus' in connection.device_type:
                # Nexus: copy running-config startup-config
                output = connection.send_command('copy running-config startup-config', expect_string=r'\[y/n\]')
                if 'y/n' in output.lower():
                    output += connection.send_command('y', expect_string=r'#')
                logger.debug(f"Save output: {output}")
            else:
                # IOS-XE: write memory
                output = connection.send_command('write memory', expect_string=r'#')
                logger.debug(f"Save output: {output}")
                
            return True
            
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            return False
            
    def verify_configuration(self, connection, switch_info, commands):
        """
        Verify that configuration changes were applied
        
        Args:
            connection: Netmiko connection object
            switch_info: Dictionary containing switch information
            commands: List of configuration commands to verify
            
        Returns:
            Boolean indicating success or failure
        """
        try:
            # This is a basic verification - you can extend this based on your needs
            # For example, check if interfaces are up, verify VLANs, etc.
            
            # Show version to confirm we're connected
            version = connection.send_command('show version', expect_string=r'#')
            logger.info(f"Verified connection to {switch_info.get('name', switch_info['host'])}")
            
            # Check running config for specific changes (basic example)
            if 'nexus' in connection.device_type:
                cmds = commands['nexus']
            else:
                cmds = commands['ios-xe']
                # Look for first command in running config
                first_cmd = cmds[0].strip()
                if not first_cmd.startswith('!'):
                    running = connection.send_command('show running-config', expect_string=r'#')
                    if first_cmd in running:
                        logger.info(f"Verified command '{first_cmd}' is present")
                        return True
                    else:
                        logger.warning(f"Command '{first_cmd}' not found in running config")
                        return False
                    
            return True
            
        except Exception as e:
            logger.error(f"Verification failed: {e}")
            return False
            
    def update_single_switch(self, switch_info):
        """
        Update a single switch with configuration
        
        Args:
            switch_info: Dictionary containing switch information
            
        Returns:
            Dictionary with update results
        """
        result = {
            'name': switch_info.get('name', switch_info['host']),
            'host': switch_info['host'],
            'success': False,
            'error': None
        }
        
        connection = None
        
        try:
            # Connect to switch
            connection = self.connect_to_device(switch_info)
            if not connection:
                result['error'] = "Connection failed"
                return result
                
            # Backup current configuration
            backup = self.backup_configuration(connection, switch_info.get('name', switch_info['host']))
            if not backup:
                result['error'] = "Backup failed"
                return result
                
            # Apply configuration updates
            if self.update_configuration(connection, switch_info, self.config_commands):
                result['success'] = True
                
                # Verify configuration
                self.verify_configuration(connection, switch_info, self.config_commands)
            else:
                result['error'] = "Configuration update failed"
                
        except Exception as e:
            logger.error(f"Error updating {switch_info.get('name', switch_info['host'])}: {e}")
            result['error'] = str(e)
            
        finally:
            if connection:
                connection.disconnect()
                
        return result
        
    def update_all_switches(self, max_workers=5):
        """
        Update all switches in parallel
        
        Args:
            max_workers: Maximum number of concurrent connections
            
        Returns:
            Dictionary with update results
        """
        logger.info(f"Starting update of {len(self.switches)} switches")
        
        if not self.switches:
            logger.warning("No switches configured")
            return {}
            
        results = {}
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all update tasks
            future_to_switch = {
                executor.submit(self.update_single_switch, switch): switch 
                for switch in self.switches
            }
            
            # Process results as they complete
            for future in as_completed(future_to_switch):
                switch = future_to_switch[future]
                try:
                    result = future.result()
                    results[switch['host']] = result
                    
                    if result['success']:
                        logger.info(f"✅ Successfully updated {result['name']}")
                    else:
                        logger.error(f"❌ Failed to update {result['name']}: {result.get('error', 'Unknown error')}")
                        
                except Exception as e:
                    logger.error(f"Error processing {switch['host']}: {e}")
                    results[switch['host']] = {
                        'name': switch.get('name', switch['host']),
                        'host': switch['host'],
                        'success': False,
                        'error': str(e)
                    }
                    
        # Generate summary
        self.generate_summary(results)
        return results
        
    def generate_summary(self, results):
        """
        Generate and log summary of updates
        
        Args:
            results: Dictionary with update results
        """
        total = len(results)
        successful = sum(1 for r in results.values() if r['success'])
        failed = total - successful
        
        logger.info("=" * 50)
        logger.info("UPDATE SUMMARY")
        logger.info("=" * 50)
        logger.info(f"Total switches: {total}")
        logger.info(f"Successful: {successful}")
        logger.info(f"Failed: {failed}")
        
        if failed > 0:
            logger.info("\nFailed switches:")
            for host, result in results.items():
                if not result['success']:
                    logger.info(f"  - {result['name']} ({host}): {result.get('error', 'Unknown error')}")
                    
        # Save results to JSON file
        results_file = f"update_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"\nDetailed results saved to {results_file}")
        logger.info("=" * 50)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Deploy configurations using YAML configuration file on Cisco switches"
    )
    
    # Connection arguments
    parser.add_argument("--file", "-f", required=True,
                        help="YAMl configuration file with switch details and commands")
    parser.add_argument("--username", "-u", type=str,
                        help="Cisco Admin username")
    parser.add_argument("--password", "-p", type=str,
                        help="Cisco Admin password")
    
    return parser.parse_args()

def main():
    """
    Main function to execute the switch update
    """
    args = parse_arguments()

    config_file = f"{basePath}/cfg_data/{args.file}"

    if not os.path.exists(config_file):
        logger.info("Configuration file not exists")
        sys.exit(0)
        
    # Initialize updater
    updater = CiscoSwitchDeployer(config_file)
    
    # Load configuration
    if not updater.load_configuration():
        logger.error("Failed to load configuration")
        sys.exit(1) 
    # Update switches
    results = updater.update_all_switches()
    
    # Exit with appropriate code
    if all(r['success'] for r in results.values()):
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
