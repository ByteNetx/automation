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
from panos.panorama import Panorama, DeviceGroup, PanoramaCommit
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
    PRE_RULE = "pre-rulebase"
    POST_RULE = "post-rulebase"

    @classmethod
    def from_string(cls, value: str) -> 'RuleType':
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(f"Invalid rulebase type: {value}. Must be 'pre-rulebase' or 'post-rulebase'")

class PanoramaRuleManager:
    """
    A class to manage security rules in a Panorama Pre-Rulebase or Post-Rulebase.
    """

    def __init__(self, hostname: str, username: str=None, password: str=None,
                     api_key: str=None, audit_comment: str=None, commit_changes: bool=False, **kwargs):

        """
        Initializes the Panorama connection.

        Args:
            hostname: Panorama hostname or IP address
            username: Username for authentication (optional if api_key provided)
            password: Password for authentication (optional if api_key provided)
            api_key: API key for authentication (optional)
            audit_comment: Audit comment for the given rule (Only required for create/update rules)
            commit_changes: Whether to commit changes
        """
        self.hostname = hostname
        self.username = username
        self.audit_comment = audit_comment
        self.commit_changes = commit_changes
        self.scope = None
        self.rulebase = None

        if api_key:
            self.panorama = Panorama(hostname, api_key=api_key)
        elif username and password:
            self.panorama = Panorama(hostname, api_username=username, api_password=password)


    def _get_device_group(self, device_group_name: str):
            """Find and return a device group object."""
            device_groups = DeviceGroup.refreshall(self.panorama)
    
            for dg in device_groups:
                if dg.name == device_group_name:
                    return dg
            return None

    def _get_existing_rule(self, rule_name: str):
        """
        Helper to fetch an existing security rule by name from the rulebase.

        Args:
            rulebase_type (str): Rulebase type either 'pre-rulebase' or 'post-rulebase'.
            rule_name (str): The name of the rule to find.

        Returns:
            SecurityRule or None: The rule object if found, else None.
        """

        # refreshall returns a list of all SecurityRule objects in the rulebase
        #if RuleType.from_string(rulebase_type).value == "pre-rulebase":
        #    rulebase = PreRulebase()
        #elif RuleType.from_string(rulebase_type).value == "post-rulebase":
        #    rulebase = PostRulebase()

        self.scope.add(self.rulebase)
        existing_rules = SecurityRule.refreshall(self.rulebase)
        for rule in existing_rules:
            if rule.name == rule_name:
                return rule

        return None

    def create_or_update_rule(self, rule_params: Dict):
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
            'group': 'spg-user-internet'
            'action': 'allow',
            'description': 'allow mgmt ssh',
            'disabled': 'False'
        }

        Args:
            rulebase_type (str): Rulebase type either 'pre-rulebase' or 'post-rulebase'.
            rule_params (dict): A dictionary of rule attributes.
        """
        rule_name = rule_params.get('name')
        # Check if the rule already exists
        existing_rule = self._get_existing_rule(rule_name)

        if existing_rule:
            logger.info(f"Rule '{existing_rule.name}' already exists, updating...")
            # Update the existing object's attributes with new values
            update_params = {k: v for k, v in rule_params.items() if k != "name"}
            for key, value in update_params.items():
                if hasattr(existing_rule, key):
                    setattr(existing_rule, key, value)
            
            try:
                # Apply the changes to Panorama
                existing_rule.apply()
                RuleAuditComment(existing_rule).update(self.audit_comment)
                logger.info(f"Rule '{existing_rule.name}' updated successfully.")
                return True
            except Exception as e:
                logger.error(f"Failed to update rule '{rule_name}: {e}")
                return False
        else:
            logger.info(f"Rule '{rule_name}' does not exist, creating...")
            # Create a new SecurityRule object
            self.scope.add(self.rulebase)
            new_rule = SecurityRule(**rule_params)
            self.rulebase.add(new_rule)
            
            try:
                # Create the rule on Panorama
                new_rule.create()
                RuleAuditComment(new_rule).update(self.audit_comment)
                logger.info(f"Rule '{new_rule.name}' created successfully.")
                return True
            except Exception as e:
                logger.error(f"Failed to create rule '{rule_name}: {e}")
                return False

    def move_rule(self, rule_name: str, move_params: Dict):
        """
        Moves a rule to a specific position within the rulebase.

        The move_params dictionary should contain the standard parameters.
        Args:
            rule_name (str): The name of the rule to move.
            location (str): Location is 'top', 'bottom', 'before' or 'after'.
            ref (str): The name of target rule, which is required for 'before' or 'after' locations.
        """
        existing_rule = self._get_existing_rule(rule_name)
        if not existing_rule:
            logger.error(f"Rule '{rule_name}' does not exist.")
            return False

        try:
            existing_rule.move(**move_params)
            logger.info(f"Rule '{existing_rule.name}' moved successfully.")
            return True
        except Exception as e:
            logger.error(f"Failed to move rule '{rule_name}': {e}")
            return False

    def delete_rule(self, rule_name: str):
        """
        Deletes a rule from the rulebase.

        Args:
            rule_name (str): The name of the rule to delete.
        """
        existing_rule = self._get_existing_rule(rule_name)
        if not existing_rule:
            logger.error(f"Rule '{rule_name}' does not exist.")
            return False

        try:
            existing_rule.delete()
            logger.info(f"Rule '{rule_name}' deleted successfully.")
            return True
        except Exception as e:
            logger.error(f"Failed to delete rule '{rule_name}': {e}")
            return False

    def list_rule(self, rule_name: str):
        """
        Search a rule from the rulebase.

        Args:
            rule_name (str): The name of the rule to search.
        """
        existing_rule = self._get_existing_rule(rule_name)

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
                elif device_group_name == "Shared":
                    self.scope = self.panorama

                if operation == OperationType.from_string('create').value and objects:
                    # Create/update rules
                    logger.info("=" * 60)
                    logger.info(f"Creating/updating rules in '{device_group_name}'")
                    logger.info("=" * 60)
                    pattern = r"^(CHG|RITM|INC)[0-9]{7}"
                    if self.audit_comment:
                        if not re.fullmatch(pattern, self.audit_comment):
                            logger.error(f"Invalid rule audit comment")
                            return results

                        for rule_type, values in objects.items():

                            self.rulebase = None

                            if rule_type == RuleType.from_string("pre-rulebase").value:
                                self.rulebase = PreRulebase()
                            elif rule_type == RuleType.from_string("post-rulebase").value:
                                self.rulebase = PostRulebase()

                            if self.rulebase != None:
                                for rule in values.get('rulebase'):
                                    name = rule.get("name")
                                    if name:
                                        rule_params = {k: v for k, v in rule.items()}
                                        success = self.create_or_update_rule(rule_params)

                                        if values.get('move'):
                                            move_params = values.get('move')
                                            success = self.move_rule(name, move_params)

                                        results[f"{rule_type.lower()}_{name}"] = success
                            else:
                                logger.error(f"Invalid rulebase {rule_type}")

                    else:
                        logger.error(f"The rule audit comment is required to create/update rules")
                        return results
     
                elif operation == OperationType.from_string('delete').value and objects:
                    # Delete rules
                    logger.info("=" * 60)
                    logger.info(f"Deleting rules in '{device_group_name}'")
                    logger.info("=" * 60)
                    for rule_type, values in objects.items():

                        self.rulebase = None

                        if rule_type == RuleType.from_string("pre-rulebase").value:
                            self.rulebase = PreRulebase()
                        elif rule_type == RuleType.from_string("post-rulebase").value:
                            self.rulebase = PostRulebase()

                        if self.rulebase != None:
                            for rule in values.get('rulebase'):
                                name = rule.get("name")
                                if name:
                                    success = self.delete_rule(name)
                                    results[f"{rule_type.lower()}_{name}"] = success
                        else:
                            logger.error(f"Invalid rulebase {rule_type}")

                elif operation == OperationType.from_string('move').value:
                    # Move rules
                    logger.info("=" * 60)
                    logger.info(f"Moving rules in '{device_group_name}'")
                    logger.info("=" * 60)
                    for rule_type, values in objects.items():
                        self.rulebase = None

                        if rule_type == RuleType.from_string("pre-rulebase").value:
                            self.rulebase = PreRulebase()
                        elif rule_type == RuleType.from_string("post-rulebase").value:
                            self.rulebase = PostRulebase()

                        if self.rulebase != None and values.get('move'):
                            move_params = values.get('move')
                            
                            for rule in values.get('rulebase'):
                                name = rule.get("name")
                                if name:
                                    success = self.move_rule(name, move_params)
                                    results[f"{rule_type.lower()}_{name}"] = success

                        else:
                            logger.error(f"Invalid rulebase {rule_type} or missing move action")

                elif operation == OperationType.from_string('list').value and objects:
                    # Search rules
                    logger.info("=" * 60)
                    logger.info(f"Searching rules in '{device_group_name}'")
                    logger.info("=" * 60)
                    for rule_type, values in objects.items():
                        self.rulebase = None

                        if rule_type == RuleType.from_string("pre-rulebase").value:
                            self.rulebase = PreRulebase()
                        elif rule_type == RuleType.from_string("post-rulebase").value:
                            self.rulebase = PostRulebase()

                        if self.rulebase != None:
                            for rule in values.get('rulebase'):
                                name = rule.get("name")
                                if name:
                                    success = self.list_rule(name)
                                    results[f"{rule_type.lower()}_{name}"] = success


            if any(operation == op for op in [OperationType.from_string('create').value, OperationType.from_string('delete').value, OperationType.from_string('move')]) and results:
                # Commit changes if requested
                if self.commit_changes:
                    logger.info("Committing changes...")
                    self.panorama.commit(admins=[self.username], sync=True)
                    logger.info("Commit completed successfully")
                else:
                    logger.info("Updated candidate configuration. Changes not committed")

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
    parser.add_argument("--commit", action='store_true',
                                    help="Enable commit")

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
    COMMIT = args.commit
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
                audit_comment=AUDIT_COMMENT,
                commit_changes=COMMIT
            )
        elif not API_KEY and not USERNAME:
            credentails = get_secret(VAULT, vaultpath)
            API_KEY = credentails.get("pano_apikey")
            manager = PanoramaRuleManager(
                hostname=PANORAMA_HOST,
                api_key=API_KEY,
                audit_comment=AUDIT_COMMENT,
                commit_changes=COMMIT
            )
        elif USERNAME:
            if not PASSWORD:
                credentails = get_secret(VAULT, vaultpath)
                PASSWORD = credentails.get(USERNAME)
    
            manager = PanoramaRuleManager(
                hostname=PANORAMA_HOST,
                username=USERNAME,
                password=PASSWORD,
                audit_comment=AUDIT_COMMENT,
                commit_changes=COMMIT
            )
        else:
            logger.error("Missing parameters required to connect Panorama")
            sys.exit()

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
