#!/usr/bin/env python3
"""
Script to manage rules in either Pre-Rulebase or Post-Rulebase
in Panorama device groups using the pan-os-python SDK.
"""

import logging
import sys
import json
import os
import re
from pathlib import Path
from typing import List, Optional, Dict, Any, Union
from enum import Enum
from panos.panorama import Panorama, DeviceGroup
from panos.policies import PreRulebase, PostRulebase, SecurityRule, RuleAuditComment

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class OperationType(Enum):
    """Supported operation modes"""
    CREATE = "create"
    DELETE = "delete"
    LIST = "list"
    MOVE = "move"

    @classmethod
    def from_string(cls, value: str) -> 'OperationType':
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(f"Invalid operation: {value}. Must be 'create', 'delete', 'list', or 'move'")

class RuleType(Enum):
    """Rulebase type"""
    PRE_RULE = "PreRulebase"
    POST_RULE = "PostRulebase"

    @classmethod
    def from_string(cls, value: str) -> 'RuleType':
        try:
            return cls(value)
        except ValueError:
            raise ValueError(f"Invalid rulebase type: {value}. Must be 'PreRulebase' or 'PostRulebase'")

class PanoramaRuleManager:
    """
    A class to manage security rules in a Panorama Pre-Rulebase or Post-Rulebase.
    """

    def __init__(self, hostname: str, username: str=None, password: str=None,
                     api_key: str=None, audit_comment: str=None, **kwargs):

        """
        Initializes the Panorama connection.

        Args:
            hostname: Panorama hostname or IP address
            username: Username for authentication (optional if api_key provided)
            password: Password for authentication (optional if api_key provided)
            api_key: API key for authentication (optional)
            audit_comment: Audit comment for the given rule (Only required for create/update rules)
        """
        self.hostname = hostname
        self.audit_comment = audit_comment
        self.scope = None

        if api_key:
            self.panorama = Panorama(hostname, api_key=api_key)
        elif username and password:
            self.panorama = Panorama(hostname, api_username=username, api_password=password)


    def _get_device_group(self, device_group_name):
            """Find and return a device group object."""
            device_groups = DeviceGroup.refreshall(self.panorama)
    
            for dg in device_groups:
                if dg.name == device_group_name:
                    return dg
            return None

    def _get_existing_rule(self, rulebase_type, rule_name):
        """
        Helper to fetch an existing security rule by name from the rulebase.

        Args:
            rulebase_type (str): Rulebase type either 'PreRulebase' or 'PostRulebase'.
            rule_name (str): The name of the rule to find.

        Returns:
            SecurityRule or None: The rule object if found, else None.
        """

        # refreshall returns a list of all SecurityRule objects in the rulebase
        if RuleType.from_string(rulebase_type).value == "PreRulebase":
            rulebase = PreRulebase()
        elif RuleType.from_string(rulebase_type).value == "PostRulebase":
            rulebase = PostRulebase()
        self.scope.add(rulebase)
        existing_rules = SecurityRule.refreshall(rulebase)
        for rule in existing_rules:
            if rule.name == rule_name:
                return rule

        return None

    def create_or_update_rule(self, rulebase_type, **rule_params):
        """
        Creates a new rule or updates an existing one in the selected rulebase.

        The rule_params dictionary should contain the standard SecurityRule parameters.
        For example: {
            'name': 'allow-traffic',
            'fromzone': ['trust'],
            'tozone': ['untrust'],
            'source': ['10.0.0.1'],
            'destination': ['10.1.1.1'],
            'application': ['ssh'],
            'service': ['application-default'],
            'action': 'allow',
            'description': 'allow mgmt ssh'
        }

        Args:
            rulebase_type (str): Rulebase type either 'PreRulebase' or 'PostRulebase'.
            rule_params (dict): A dictionary of rule attributes.
        """
        rule_name = rule_params.get('name')
        # Check if the rule already exists
        existing_rule = self._get_existing_rule(rulebase_type, rule_name)

        if existing_rule:
            logger.info(f"Rule '{rule_name}' found in {rulebase_type.lower()}. Updating...")
            # Update the existing object's attributes with new values
            for key, value in rule_params.items():
                if hasattr(existing_rule, key):
                    setattr(existing_rule, key, value)
            
            try:
                # Apply the changes to Panorama
                existing_rule.apply()
                RuleAuditComment(existing_rule).update(self.audit_comment)
                logger.info(f"Rule '{rule_name}' updated successfully in {rulebase_type.lower()}.")
                return True
            except Exception as e:
                logger.error(f"Failed to update rule: {e}")
                return False
        else:
            logger.info(f"Rule '{rule_name}' not found in {rulebase_type.lower()}. Creating...")
            # Create a new SecurityRule object
            if RuleType.from_string(rulebase_type).value == "PreRulebase":
                rulebase = PreRulebase()
            elif RuleType.from_string(rulebase_type).value == "PostRulebase":
                rulebase = PostRulebase()
            self.scope.add(rulebase)
            new_rule = SecurityRule(**rule_params)
            rulebase.add(new_rule)
            
            try:
                # Create the rule on Panorama
                new_rule.create()
                RuleAuditComment(new_rule).update(self.audit_comment)
                logger.info(f"Rule '{rule_name}' created successfully in {rulebase_type.lower()}.")
                return True
            except Exception as e:
                logger.error(f"Failed to create rule: {e}")
                return False

    def move_rule(self, rulebase_type, rule_name, position, target_rule=None):
        """
        Moves a rule to a specific position within the rulebase.

        Args:
            rulebase_type (str): Rulebase type either 'PreRulebase' or 'PostRulebase'.
            rule_name (str): The name of the rule to move.
            position (str): Position either 'before' or 'after'.
            target_rule (str): The name of target rule, which isrequired for 'before' or 'after' positions.
        """
        existing_rule = self._get_existing_rule(rulebase_type, rule_name)
        if not existing_rule:
            logger.error(f"Rule '{rule_name}' not found in {rulebase_type.lower()}.")
            return

        try:
            existing_rule.move(position, target_rule)
            logger.info(f"Rule '{rule_name}' moved to {position} {target_rule} in {rulebase_type.lower()}.")
            return True
        except Exception as e:
            logger.error(f"Failed to move rule: {e}")
            return False

    def delete_rule(self, rulebase_type, rule_name):
        """
        Deletes a rule from the rulebase.

        Args:
            rulebase_type (str): Rulebase type either 'PreRulebase' or 'PostRulebase'.
            rule_name (str): The name of the rule to delete.
        """
        existing_rule = self._get_existing_rule(rulebase_type, rule_name)
        if not existing_rule:
            logger.error(f"Rule '{rule_name}' not found in {rulebase_type.lower()}.")
            return

        try:
            existing_rule.delete()
            logger.info(f"Rule '{rule_name}' deleted successfully from {rulebase_type.lower()}.")
            return True
        except Exception as e:
            logger.error(f"Failed to delete rule: {e}")
            return False

    def list_rule(self, rulebase_type, rule_name):
        """
        Search a rule from the rulebase.

        Args:
            rulebase_type (str): Rulebase type either 'PreRulebase' or 'PostRulebase'.
            rule_name (str): The name of the rule to delete.
        """
        existing_rule = self._get_existing_rule(rulebase_type, rule_name)
        if existing_rule:
            logger.info(
                existing_rule.about()
            )
            return True
        else:
            return False

    # ==================== RULE OPERATION METHODS ====================
    def rule_operation(self, operation: str, cfg_data: Dict[str, Any]) -> Dict[str, bool]:
        """
        Operation for multiple objects in cfg_data dictionary.

        Args:
            operation (str): Operation mode is create, delete, move, or list.
            cfg_data (Dict): A dictionary containing configuration for multiple objects.
  
        Returns:
            Dictionary with object names and success status
        """
    
        results = {}
        try:
            for device_group_name, objects in cfg_data.items():
                # Get the device group
                if device_group_name != "Shared":
                    device_group = self._get_device_group(device_group_name)
                    if not device_group:
                        logger.error(f"Error: '{device_group_name}' does not exist")
                        return results
                    self.scope = device_group
                else:
                    self.scope = self.panorama

                if operation == OperationType.from_string('create').value and objects:
                    # Create/update rules
                    logger.info("=" * 60)
                    logger.info(f"Creating/updating rules in '{device_group_name}'")
                    logger.info("=" * 60)
                    pattern = r"^(CHG|RITM|INC)[0-9]{7}"
                    if self.audit_comment:
                        if not re.fullmatch(pattern, self.audit_comment):
                            logger.error(f"Valid audit comment required to create/update rules")
                            return results
                        for rule_type, values in objects.items():
                            if any(rule_type == rType for rType in [RuleType.from_string("PreRulebase").value, RuleType.from_string("PostRulebase").value]):
                                for rule in values.get('rulebase'):
                                    name = rule.get("name")
                                    if name:
                                        rule_params = {k: v for k, v in rule.items() if v}
                                        
                                        success = self.create_or_update_rule(rule_type, **rule_params)

                                        if values.get('move'):
                                            position = values.get('move').get('position')
                                            target = values.get('move').get('target')
                                            if position and target:
                                                success = self.move_rule(rule_type, name, position, target)

                                        results[f"{rule_type.lower()}_{name}"] = success

                    else:
                        logger.error(f"Valid audit comment required to create/update rules")
                        return results
     
                elif operation == OperationType.from_string('delete').value and objects:
                    # Delete rules
                    logger.info("=" * 60)
                    logger.info(f"Deleting rules in '{device_group_name}'")
                    logger.info("=" * 60)
                    for rule_type, values in objects.items():
                        if any(rule_type == rType for rType in [RuleType.from_string("PreRulebase").value, RuleType.from_string("PostRulebase").value]):
                            for rule in values.get('rulebase'):
                                name = rule.get("name")
                                if name:
                                    success = self.delete_rule(rule_type, name)
                                    results[f"{rule_type.lower()}_{name}"] = success
    
                elif operation == OperationType.from_string('move').value:
                    # Move rules
                    logger.info("=" * 60)
                    logger.info(f"Moving rules in '{device_group_name}'")
                    logger.info("=" * 60)
                    for rule_type, values in objects.items():
                        if any(rule_type == rType for rType in [RuleType.from_string("PreRulebase").value, RuleType.from_string("PostRulebase").value]):
                            if values.get('move'):
                                position = values.get('move').get('position')
                                target = values.get('move').get('target')
                                if position and target:
                                    for rule in values.get('rulebase'):
                                        name = rule.get("name")
                                        if name:
                                            success = self.move_rule(rule_type, name, position, target)
                                            results[f"{rule_type.lower()}_{name}"] = success
                                else:
                                    logger.error("Missing required parameters to move rules")
                                    return results

                elif operation == OperationType.from_string('list').value and objects:
                    # Search rules
                    logger.info("=" * 60)
                    logger.info(f"Searching rules in '{device_group_name}'")
                    logger.info("=" * 60)
                    for rule_type, values in objects.items():
                        if any(rule_type == rType for rType in [RuleType.from_string("PreRulebase").value, RuleType.from_string("PostRulebase").value]):
                            for rule in values.get('rulebase'):
                                name = rule.get("name")
                                if name:
                                    success = self.list_rule(rule_type, name)
                                    results[f"{rule_type.lower()}_{name}"] = success
                return results

        except Exception as e:
            logger.error(f"Error in rule operation: {e}")
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
    parser.add_argument("--hostname", "-H", required=True,
                        help="Panorama hostname or IP address")
    parser.add_argument("--username", "-u", type=str,
                        help="Panorama admin username")
    parser.add_argument("--file", "-f", type=str,
                        help="Object configuration JSON file")
    parser.add_argument("--operation", "-o", choices=['create', 'delete', 'move', 'list'], 
                        nargs="?", const="list", default='list',
                        help="Operation commands to create/delete/move/list rulebase in Panorama Device Group. Default to 'list'")

    # Authentication arguments (either apikey or username/password)
    auth = parser.add_mutually_exclusive_group(required=False)
    auth.add_argument("--password", "-p", action=Password, nargs='?', dest='passwd',
                        help="Panorama admin password")
    auth.add_argument("--apikey", "-a", type=str,
                        help="Panorama API key")

    # Option arguments
    parser.add_argument("--audit", type=str,
                        help="Audit comments on security rule")
    parser.add_argument("--position", type=str, choices=['before', 'after'], 
                        help="Places the rule directly above or below a specific target rule")
    parser.add_argument("--target", type=str,
                        help="The name of the target rule")

    return parser.parse_args()

def get_secret(vault, vaultpath):
    from encryption import CredentialManager
    manager = CredentialManager(vault, vaultpath)
    credentails = manager.decrypt()
    return credentails

def main():
    """
    Main function to use the PanoramaRuleManager class.
    """

    args = parse_arguments()
    basePath = Path.home() / 'pyenv3.13' / 'panos' / 'pano_project'
    filepath = f"{basePath}/config/{args.file}"

    PANORAMA_HOST = args.hostname
    API_KEY = args.apikey
    USERNAME = args.username
    PASSWORD = args.passwd
    OPERATION = args.operation
    AUDIT_COMMENT = args.audit or None
    POSITION = args.position
    TARGET = args.target
    VAULT = "panos_secrets.bin"
    vaultpath = Path.home() / 'pyenv3.13' / 'secrets'
    cfg_data = {}

    # Get object data
    if os.path.isfile(filepath):
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
        if not AUDIT_COMMENT:
            AUDIT_COMMENT = data.get('audit_comment', None)
        cfg_data = {k: v for k, v in data.items() if k != "audit_comment"}
    else:
        logger.info("Error: Objects must be provided")
        sys.exit(0)


    if cfg_data:
        # Initialize the manager
        if API_KEY:
            manager = PanoramaRuleManager(
                hostname=PANORAMA_HOST,
                api_key=API_KEY,
                audit_comment=AUDIT_COMMENT
            )
        elif not API_KEY and not USERNAME:
            credentails = get_secret(VAULT, vaultpath)
            API_KEY = credentails.get("pano_apikey")
            manager = PanoramaRuleManager(
                hostname=PANORAMA_HOST,
                api_key=API_KEY,
                audit_comment=AUDIT_COMMENT
            )
        elif USERNAME:
            if not PASSWORD:
                credentails = get_secret(VAULT, vaultpath)
                PASSWORD = credentails.get(USERNAME)
    
            manager = PanoramaRuleManager(
                hostname=PANORAMA_HOST,
                username=USERNAME,
                password=PASSWORD,
                audit_comment=AUDIT_COMMENT
            )
        else:
            credentails = get_secret(VAULT, vaultpath)
            API_KEY = credentails.get("pano_apikey")
            manager = PanoramaRuleManager(
                hostname=PANORAMA_HOST,
                api_key=API_KEY,
                audit_comment=AUDIT_COMMENT
            )

        if any(OperationType.from_string(OPERATION).value == op for op in ['create', 'delete', 'move', 'list']):

            results = manager.rule_operation(OPERATION, cfg_data)
    
            logger.info("Operation results:")
            for obj_name, success in results.items():
                status = "✓" if success else "✗"
                logger.info(f"  {status} {obj_name}")

    
        logger.info("=" * 60)
        logger.info("Operations completed successfully!")
        logger.info("=" * 60)

if __name__ == "__main__":
    main()
