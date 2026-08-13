#!/usr/bin/env python3
"""
Script to manage security rules and their referenced objects
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
from panos.objects import (
    CustomUrlCategory,
    AddressObject,
    AddressGroup,
    ServiceObject,
    ServiceGroup,
    Edl
)

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

class ObjectType(Enum):
    """Object type"""
    ADDRESS = "address_object"
    ADDRESS_GROUP = "address_group"
    SERVICE = "service_object"
    SERVICE_GROUP = "service_group"
    URL_CATEGORY = "url_category"
    EDL = "external_dynamic_list"

    @classmethod
    def from_string(cls, value: str) -> 'ObjectType':
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(f"Invalid object type: {value}.")

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


class PanoramaManager:
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
        self.object_type = None
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

    def _get_existing_object(self, object_type: type, name: str):
        """
        Helper to check if an object already exists in the device group.

        Args:
            object_type: The PAN-OS object class (AddressObject, AddressGroup, etc.)
            name: Name of the object to search

        Returns:
            Object instance if found, None otherwise
        """
        objects = object_type.refreshall(self.scope)
        
        for obj in objects:
            if obj.name == name:
                return obj
        return None

    # Object Section
    #================================
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

    def create_or_update_url_category(self, name: str, url_params: Dict) -> bool:
        """
        Create a new custom URL category or update an existing one.

        The url_params dictionary should contain the standard url parameters.
        Args:
            name: (str) Name of the URL category (max 31 chars)
            url_value: (list) List of URLs or domain patterns
            description: (str) Optional description (max 255 chars)
            type: (str) "URL List" or "Category Match"

        Returns:
            True if successful, False otherwise
        """
        try:
            existing = self._get_existing_object(self.object_type, name)

            if existing:
                logger.info(f"URL Category '{existing.name}' already exists, updating...")

                for key, value in url_params.items():
                    if hasattr(existing, key):
                        setattr(existing, key, value)

                existing.apply()

                if not existing:
                    return False

            else:
                logger.info(f"URL Category '{name}' does not exist, creating...")

                new_params = {"name": name}
                new_params.update(url_params)

                new_obj = self.object_type(**new_params)
                self.scope.add(new_obj)
                new_obj.create()

                if not new_obj:
                    return False

            return True

        except Exception as e:
            logger.error(f"Error managing URL category '{name}': {e}")
            return False

    def delete_url_category(self, name: str) -> bool:
        """Delete a custom URL category."""
        try:
            existing = self._get_existing_object(self.object_type, name)
            if existing:
                existing.delete()
                logger.info(f"Deleted URL category '{name}'")
                return True
            else:
                logger.warning(f"URL category '{name}' not found")
                return False
        except Exception as e:
            logger.error(f"Error deleting URL category '{name}': {e}")
            return False

    # ==================== ADDRESS OBJECT METHODS ====================

    def create_or_update_address_object(self, name: str, address_params: Dict) -> bool:
        """
        Create or update an address object.

        The address_params dictionary should contain the standard address object parameters.
        Args:
            name: (str) Name of the address object
            type: (str) Type of address is ip-netmask (default), ip-range, ip-wildcard, or fqdn
            value: (str) IP address or other value of the object
            description: (str) Optional description

        Returns:
            True if successful, False otherwise
        """
        try:

            existing = self._get_existing_object(self.object_type, name)

            if existing:
                logger.info(f"Address Object '{existing.name}' already exists, updating...")

                for key, value in address_params.items():
                    if hasattr(existing, key):
                        setattr(existing, key, value)

                existing.apply()

                if not existing:
                    return False

            else:
                logger.info(f"Address Object '{name}' does not exist, creating...")

                new_params = {"name": name}
                new_params.update(address_params)

                new_obj = self.object_type(**new_params)
                self.scope.add(new_obj)
                new_obj.create()

                if not new_obj:
                    return False

            return True

        except Exception as e:
            logger.error(f"Error managing address object '{name}': {e}")
            return False

    def delete_address_object(self, name: str) -> bool:
        """Delete an address object."""
        try:
            existing = self._get_existing_object(self.object_type, name)
            if existing:
                existing.delete()
                logger.info(f"Deleted address object '{name}'")
                return True
            else:
                logger.warning(f"Address object '{name}' not found")
                return False
        except Exception as e:
            logger.error(f"Error deleting address object '{name}': {e}")
            return False

    # ==================== ADDRESS GROUP METHODS ====================

    def create_or_update_static_address_group(self, name: str,
                                              member_names: List[str],
                                              description: str = None) -> bool:
        """
        Create or update a static address group.

        Args:
            name: Name of the address group
            member_names: List of address object names to include in the group
            description: Optional description

        Returns:
            True if successful, False otherwise
        """
        try:
            # Validate that all members exist
            for member in member_names:
                if not self._get_existing_object(AddressObject, member):
                    logger.warning(f"Address object '{member}' does not exist. It will be created as a placeholder.")

            existing = self._get_existing_object(self.object_type, name)

            if existing:
                logger.info(f"Address Group '{name}' already exists, updating...")
                existing.static_value = member_names
                if description:
                    existing.description = description
                existing.apply()
                if not existing:
                    return False
            else:
                logger.info(f"Address Group '{name}' does not exist, creating...")
                new_obj = self.object_type(
                    name=name,
                    static_value=member_names,
                    description=description
                )
                self.scope.add(new_obj)
                new_obj.create()
                if not new_obj:
                    return False

            return True

        except Exception as e:
            logger.error(f"Error managing address group '{name}': {e}")
            return False

    def create_or_update_dynamic_address_group(self, name: str,
                                               filter_criteria: str,
                                               description: str = None) -> bool:
        """
        Create or update a dynamic address group.

        Args:
            name: Name of the dynamic address group
            filter_criteria: Dynamic filter (e.g., "tag1 or tag2")
            description: Optional description

        Returns:
            True if successful, False otherwise
        """
        try:
            existing = self._get_existing_object(self.object_type, name)

            if existing:
                logger.info(f"Dynamic Address Group '{name}' already exists, updating...")
                existing.dynamic_value = filter_criteria
                if description:
                    existing.description = description
                existing.apply()
                if not existing:
                    return False
            else:
                logger.info(f"Dynamic Address Group '{name}' does not exist, creating...")
                new_obj = self.object_type(
                    name=name,
                    dynamic_value=filter_criteria,
                    description=description
                )
                self.scope.add(new_obj)
                new_obj.create()
                if not new_obj:
                    return False

            return True

        except Exception as e:
            logger.error(f"Error managing dynamic address group '{name}': {e}")
            return False

    def delete_address_group(self, name: str) -> bool:
        """Delete an address group (static or dynamic)."""
        try:
            # Try address group first
            existing = self._get_existing_object(self.object_type, name)
            if existing:
                existing.delete()
                logger.info(f"Deleted address group '{name}'")
                return True

            logger.warning(f"Address group '{name}' not found")
            return False

        except Exception as e:
            logger.error(f"Error deleting address group '{name}': {e}")
            return False

    # ==================== SERVICE OBJECT METHODS ====================

    def create_or_update_service_object(self, name: str, service_params: Dict) -> bool:
        """
        Create or update an service object.

        The service_params dictionary should contain the standard service object parameters.
        Args:
            name: Name of the service object
            protocol: Protocol of the service, either tcp or udp
            destination_port: Destination port of the service
            description: Optional description

        Returns:
            True if successful, False otherwise
        """
        try:
            existing = self._get_existing_object(self.object_type, name)

            if existing:
                logger.info(f"Service Object '{existing.name}' already exists, updating...")

                for key, value in service_params.items():
                    if hasattr(existing, key):
                        setattr(existing, key, value)

                existing.apply()

                if not existing:
                    return False

            else:
                logger.info(f"Service Object '{name}' does not exist, creating...")

                new_params = {"name": name}
                new_params.update(service_params)

                new_obj = self.object_type(**new_params)
                self.scope.add(new_obj)
                new_obj.create()

                if not new_obj:
                    return False                

            return True

        except Exception as e:
            logger.error(f"Error managing service object '{name}': {e}")
            return False

    def delete_service_object(self, name: str) -> bool:
        """Delete an service object."""
        try:
            existing = self._get_existing_object(self.object_type, name)
            if existing:
                existing.delete()
                logger.info(f"Deleted service object '{name}'")
                return True
            else:
                logger.warning(f"Service object '{name}' not found")
                return False
        except Exception as e:
            logger.error(f"Error deleting service object '{name}': {e}")
            return False

    # ==================== SERVICE GROUP METHODS ====================

    def create_or_update_service_group(self, name: str, value: List[str]) -> bool:
        """
        Create or update an service object.

        Args:
            name: Name of the service group
            member_names: List of service objects

        Returns:
            True if successful, False otherwise
        """
        try:
            existing = self._get_existing_object(self.object_type, name)

            if existing:
                logger.info(f"Service Group '{name}' already exists, updating...")
                existing.value = value
                existing.apply()
                if not existing:
                    return False
            else:
                logger.info(f"Service Group '{name}' does not exist, creating...")
                new_obj = self.object_type(
                    name=name,
                    value=value
                )
                self.scope.add(new_obj)
                new_obj.create()
                if not new_obj:
                    return False

            return True

        except Exception as e:
            logger.error(f"Error managing service group '{name}': {e}")
            return False

    def delete_service_group(self, name: str) -> bool:
        """Delete an service group."""
        try:
            existing = self._get_existing_object(self.object_type, name)
            if existing:
                existing.delete()
                logger.info(f"Deleted service group '{name}'")
                return True
            else:
                logger.warning(f"Service group '{name}' not found")
                return False
        except Exception as e:
            logger.error(f"Error deleting service group '{name}': {e}")
            return False

    # ==================== EXTERNAL DYNAMIC LIST METHODS ====================

    def create_or_update_edl(self, name: str, edl_params: Dict) -> bool:
        """
        Create a new External Dynamic List or update an existing one.

        The edl_params dictionary should contain the standard edl parameters.
        Args:
            name: (str) Name of the External Dynamic List
            edl_type: (str) must be one of : "ip", "url", or "domain"
            source: (str) Source of edl
            repeat: (str) Retrieval interval. Valid values are “five-minute”, “hourly”, “daily”, “weekly”, or “monthly”.
            description: (str) Optional description
            certificate_profile: (str) Profile for authenticating client certificates
            username: (str) Username for authentication
            password: (str) Password for authentication

        Returns:
            True if successful, False otherwise
        """
        try:
            existing = self._get_existing_object(self.object_type, name)

            if existing:
                logger.info(f"External Dynamic List '{existing.name}' already exists, updating...")

                for key, value in edl_params.items():
                    if hasattr(existing, key):
                        setattr(existing, key, value)

                existing.apply()

                if not existing:
                    return False

            else:
                logger.info(f"External Dynamic list '{name}' does not exist, creating...")

                new_params = {"name": name}
                new_params.update(edl_params)

                new_obj = self.object_type(**new_params)
                self.scope.add(new_obj)
                new_obj.create()

                if not new_obj:
                    return False

            return True

        except Exception as e:
            logger.error(f"Error managing External Dynamic List '{name}': {e}")
            return False

    def delete_edl(self, name: str) -> bool:
        """Delete an external dynamic list."""
        try:
            existing = self._get_existing_object(self.object_type, name)
            if existing:
                existing.delete()
                logger.info(f"Deleted external dynamic list '{name}'")
                return True
            else:
                logger.warning(f"External dynamic list '{name}' not found")
                return False
        except Exception as e:
            logger.error(f"Error deleting external dynamic list '{name}': {e}")
            return False

    # Security Rule Section
    #================================
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

    # Operation section
    #================================
    def run_operation(self, operation: str, cfg_data: Dict[str, Any]) -> Dict[str, bool]:
        """
        Operation for multiple objects in the object_config dictionary.

        Args:
            operation: Operation mode is 'create', 'delete' or 'list'.
            objects_config: Dictionary containing configuration for multiple objects

        Returns:
            Dictionary with object names and success status
        """
        results = {}

        try:
            for device_group_name, object_data in cfg_data.items():
                # Set the scope for objects
                if device_group_name != "Shared":
                    device_group = self._get_device_group(device_group_name)
                    if not device_group:
                        logger.error(f"Error: '{device_group_name}' does not exist")
                        return results
                    self.scope = device_group
                elif device_group_name == "Shared":
                    self.scope = self.panorama

                if operation == OperationType.from_string('create').value and object_data:
                    if ObjectType.from_string("address_object").value in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Creating/updating address objects in '{device_group_name}'")
                        logger.info("=" * 60)
                        self.object_type = AddressObject
                        for object in object_data["address_object"]:
                            name = object.get("name")
                            if name:
                                addr_params = {k: v for k, v in object.items() if k != "name"}
                                success = self.create_or_update_address_object(name, addr_params)
                                results[f"address_object_{name}"] = success
                    if ObjectType.from_string("url_category").value in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Creating/updating custom urls in '{device_group_name}'")
                        logger.info("=" * 60)
                        self.object_type = CustomUrlCategory
                        for object in object_data["url_category"]:
                            name = object.get("name")
                            if name:
                                url_params = {k: v for k, v in object.items() if k != "name"}
                                success = self.create_or_update_url_category(name, url_params)
                                results[f"url_category_{name}"] = success
    
                    if ObjectType.from_string("address_group").value in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Creating/updating address groups in '{device_group_name}'")
                        logger.info("=" * 60)
                        self.object_type = AddressGroup
                        for object in object_data["address_group"]:
                            name = object.get("name")
                            if name:
                                addr_group_params = {k: v for k, v in object.items() if k != "name"}
                                if "filter_criteria" in addr_group_params:
                                    success = self.create_or_update_dynamic_address_group(name, **addr_group_params)
                                else:
                                    success = self.create_or_update_static_address_group(name, **addr_group_params)
                                results[f"address_group_{name}"] = success
                
                    if ObjectType.from_string("service_object").value in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Creating/updating service objects in '{device_group_name}'")
                        logger.info("=" * 60)
                        self.object_type = ServiceObject
                        for object in object_data["service_object"]:
                            name = object.get("name")
                            if name:
                                serv_params = {k: v for k, v in object.items() if k != "name"}
                                success = self.create_or_update_service_object(name, serv_params)
                                results[f"service_object_{name}"] = success

                    if ObjectType.from_string("service_group").value in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Creating/updating service groups in '{device_group_name}'")
                        logger.info("=" * 60)
                        self.object_type = ServiceGroup
                        for object in object_data["service_group"]:
                            name = object.get("name")
                            if name:
                                serv_group_params = {k: v for k, v in object.items() if k != "name"}
                                success = self.create_or_update_service_group(name, **serv_group_params)
                                results[f"service_group_{name}"] = success

                    if ObjectType.from_string("external_dynamic_list").value in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Creating/updating edls in '{device_group_name}'")
                        logger.info("=" * 60)
                        self.object_type = Edl
                        for object in object_data["external_dynamic_list"]:
                            name = object.get("name")
                            if name:
                                edl_params = {k: v for k, v in object.items() if k != "name"}
                                success = self.create_or_update_edl(name, edl_params)
                                results[f"edl_{name}"] = success

                    if RuleType.from_string("pre-rulebase").value in object_data:
                        self.rulebase = PreRulebase()

                        pattern = r"^(CHG|RITM|INC)[0-9]{7}"
                        if self.audit_comment:
                            if not re.fullmatch(pattern, self.audit_comment):
                                logger.error(f"Invalid rule audit comment")
                                return results
                        else:
                            logger.error("Missing rule audit comment")
                            return results

                        logger.info("=" * 60)
                        logger.info(f"Creating/updating rules in '{device_group_name}'")
                        logger.info("=" * 60)
                        for rule in object_data["pre-rulebase"]:
                            name = rule.get("name")
                            move_params = rule.get("move", {})
                            if name:
                                rule_params = {k: v for k, v in rule.items() if k != "move" and v}
                                success = self.create_or_update_rule(rule_params)

                                if move_params:
                                    success = self.move_rule(name, move_params)

                                    results[f"pre-rulebase_{name}"] = success

                    if RuleType.from_string("post-rulebase").value in object_data:
                        self.rulebase = PostRulebase()

                        pattern = r"^(CHG|RITM|INC)[0-9]{7}"
                        if self.audit_comment:
                            if not re.fullmatch(pattern, self.audit_comment):
                                logger.error(f"Invalid rule audit comment")
                                return results
                        else:
                            logger.error("Missing rule audit comment")
                            return results

                        logger.info("=" * 60)
                        logger.info(f"Creating/updating rules in '{device_group_name}'")
                        logger.info("=" * 60)
                        for rule in object_data["post-rulebase"]:
                            name = rule.get("name")
                            move_params = rule.get("move", {})
                            if name:
                                rule_params = {k: v for k, v in rule.items() if k != "move" and v}
                                success = self.create_or_update_rule(rule_params)

                                if move_params:
                                    success = self.move_rule(name, move_params)

                                    results[f"post-rulebase_{name}"] = success

                elif operation == OperationType.from_string('delete').value and object_data:
                    if RuleType.from_string("pre-rulebase").value in object_data:
                        self.rulebase = PreRulebase()

                        logger.info("=" * 60)
                        logger.info(f"Deleting rules in '{device_group_name}'")
                        logger.info("=" * 60)
                        for rule in object_data["pre-rulebase"]:
                            name = rule.get("name")
                            if name:
                                success = self.delete_rule(name)
                                results[f"pre-rulebase_{name}"] = success

                    if RuleType.from_string("post-rulebase").value in object_data:
                        self.rulebase = PostRulebase()

                        logger.info("=" * 60)
                        logger.info(f"Deleting rules in '{device_group_name}'")
                        logger.info("=" * 60)
                        for rule in object_data["post-rulebase"]:
                            name = rule.get("name")
                            if name:
                                success = self.delete_rule(name)
                                results[f"post-rulebase_{name}"] = success

                    if ObjectType.from_string("address_group").value in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Deleting address groups in '{device_group_name}'")
                        logger.info("=" * 60)
                        self.object_type = AddressGroup
                        for object in object_data["address_group"]:
                            name = object.get("name")
                            if name:
                                success = self.delete_address_group(name)
                                results[f"address_group_{name}"] = success

                    if ObjectType.from_string("address_object").value in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Deleting address objects in '{device_group_name}'")
                        logger.info("=" * 60)
                        self.object_type = AddressObject
                        for object in object_data["address_object"]:
                            name = object.get("name")
                            if name:
                                success = self.delete_address_object(name)
                                results[f"address_object_{name}"] = success
    
                    if ObjectType.from_string("url_category").value in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Deleting custom urls in '{device_group_name}'")
                        logger.info("=" * 60)
                        self.object_type = CustomUrlCategory
                        for object in object_data["url_category"]:
                            name = object.get("name")
                            if name:
                                success = self.delete_url_category(name)
                                results[f"url_category_{name}"] = success

                    if ObjectType.from_string("service_group").value in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Deleting service groups in '{device_group_name}'")
                        logger.info("=" * 60)
                        self.object_type = ServiceGroup
                        for object in object_data["service_group"]:
                            name = object.get("name")
                            if name:
                                success = self.delete_service_group(name)
                                results[f"service_group_{name}"] = success
                    if ObjectType.from_string("service_object").value in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Deleting service objects in '{device_group_name}'")
                        logger.info("=" * 60)
                        self.object_type = ServiceObject
                        for object in object_data["service_object"]:
                            name = object.get("name")
                            if name:
                                success = self.delete_service_object(name)
                                results[f"service_object_{name}"] = success

                    if ObjectType.from_string("external_dynamic_list").value in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Deleting edls in '{device_group_name}'")
                        logger.info("=" * 60)
                        self.object_type = Edl
                        for object in object_data["external_dynamic_list"]:
                            name = object.get("name")
                            if name:
                                success = self.delete_edl(name)
                                results[f"edl_{name}"] = success
                elif operation == OperationType.from_string('list').value and object_data:
                    if ObjectType.from_string("address_group").value in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Searching address groups in '{device_group_name}'")
                        logger.info("=" * 60)
                        self.object_type = AddressGroup
                        for object in object_data["address_group"]:
                            name = object.get("name")
                            if name:
                                existing = self._get_existing_object(self.object_type, name)
                                if existing:
                                    success = True
                                    logger.info(existing.about())
                                else:
                                    success = False
                                results[f"address_group_{name}"] = success

                    if ObjectType.from_string("address_object").value in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Searching address objects in '{device_group_name}'")
                        logger.info("=" * 60)
                        self.object_type = AddressObject
                        for object in object_data["address_object"]:
                            name = object.get("name")
                            if name:
                                existing = self._get_existing_object(self.object_type, name)
                                if existing:
                                    success = True
                                    logger.info(existing.about())
                                else:
                                    success = False
                                results[f"address_object_{name}"] = success
                            
    
                    if ObjectType.from_string("url_category").value in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Searching custom urls in '{device_group_name}'")
                        logger.info("=" * 60)
                        self.object_type = CustomUrlCategory
                        for object in object_data["url_category"]:
                            name = object.get("name")
                            if name:
                                existing = self._get_existing_object(self.object_type, name)
                                if existing:
                                    success = True
                                    logger.info(existing.about())
                                else:
                                    success = False
                                results[f"url_category_{name}"] = success

                    if ObjectType.from_string("service_group").value in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Searching service groups in '{device_group_name}'")
                        logger.info("=" * 60)
                        self.object_type = ServiceGroup
                        for object in object_data["service_group"]:
                            name = object.get("name")
                            if name:
                                existing = self._get_existing_object(self.object_type, name)
                                if existing:
                                    success = True
                                    logger.info(existing.about())
                                else:
                                    success = False
                                results[f"service_group_{name}"] = success

                    if ObjectType.from_string("service_object").value in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Searching service objects in '{device_group_name}'")
                        logger.info("=" * 60)
                        self.object_type = ServiceObject
                        for object in object_data["service_object"]:
                            name = object.get("name")
                            if name:
                                existing = self._get_existing_object(self.object_type, name)
                                if existing:
                                    success = True
                                    logger.info(existing.about())
                                else:
                                    success = False
                                results[f"service_object_{name}"] = success

                    if ObjectType.from_string("external_dynamic_list").value in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Searching edls in '{device_group_name}'")
                        logger.info("=" * 60)
                        self.object_type = Edl
                        for object in object_data["external_dynamic_list"]:
                            name = object.get("name")
                            if name:
                                existing = self._get_existing_object(self.object_type, name)
                                if existing:
                                    success = True
                                    logger.info(existing.about())
                                else:
                                    success = False
                                results[f"edl_{name}"] = success

                    if RuleType.from_string("pre-rulebase").value in object_data:
                        self.rulebase = PreRulebase()

                        logger.info("=" * 60)
                        logger.info(f"Searching rules in '{device_group_name}'")
                        logger.info("=" * 60)
                        for rule in object_data["pre-rulebase"]:
                            name = rule.get("name")
                            if name:
                                success = self.list_rule(name)
                                results[f"pre-rulebase_{name}"] = success

                    if RuleType.from_string("post-rulebase").value in object_data:
                        self.rulebase = PostRulebase()

                        logger.info("=" * 60)
                        logger.info(f"Searching rules in '{device_group_name}'")
                        logger.info("=" * 60)
                        for rule in object_data["post-rulebase"]:
                            name = rule.get("name")
                            if name:
                                success = self.list_rule(name)
                                results[f"post-rulebase_{name}"] = success

                elif operation == OperationType.from_string('move').value and object_data:
                    if RuleType.from_string("pre-rulebase").value in object_data:
                        self.rulebase = PreRulebase()

                        logger.info("=" * 60)
                        logger.info(f"Moving rules in '{device_group_name}'")
                        logger.info("=" * 60)
                        for rule in object_data["pre-rulebase"]:
                            name = rule.get("name")
                            move_params = rule.get("move", {})
                            if name and move_params:
                                success = self.move_rule(name, move_params)
                                results[f"pre-rulebase_{name}"] = success

                    if RuleType.from_string("post-rulebase").value in object_data:
                        self.rulebase = PostRulebase()

                        logger.info("=" * 60)
                        logger.info(f"Moving rules in '{device_group_name}'")
                        logger.info("=" * 60)
                        for rule in object_data["post-rulebase"]:
                            name = rule.get("name")
                            move_params = rule.get("move", {})
                            if name and move_params:
                                success = self.move_rule(name, move_params)
                                results[f"post-rulebase_{name}"] = success
    
            if any(operation == op for op in [OperationType.from_string('create').value, OperationType.from_string('delete').value]) and results:
                # Commit changes if requested
                confirm = [k for k, v in results.items() if v is False]
                if self.commit_changes and not confirm:
                    logger.info("Committing changes...")
                    self.panorama.commit(admins=[self.username], sync=True)
                    logger.info("Commit completed successfully")
                else:
                    logger.info("Updated candidate configuration. Changes not committed")


            return results

        except Exception as e:
            logger.error(f"Error in object operation: {e}")
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
        description="Arguments to run PanoramaManager script"
    )
    
    # Common arguments
    parser.add_argument("--hostname", "-H", required=True,
                        help="Panorama hostname or IP address")
    parser.add_argument("--username", "-u", type=str,
                        help="Panorama admin username")
    parser.add_argument("--file", "-f", type=str,
                        help="The name of JSON configuration file")
    parser.add_argument("--operation", "-o", choices=['create', 'delete', 'move', 'list'], 
                        nargs="?", const="list", default='list',
                        help="Operation modes are create, delete, move, or list. Default to 'list'")

    # Authentication arguments (either apikey or username/password)
    auth = parser.add_mutually_exclusive_group(required=False)
    auth.add_argument("--password", "-p", action=Password, nargs='?', dest='passwd',
                        help="Panorama admin password")
    auth.add_argument("--apikey", "-a", type=str,
                        help="Panorama API key")

    # Option arguments
    parser.add_argument("--audit", type=str,
                        help="Rule audit comments")
    parser.add_argument("--commit", action='store_true',
                                    help="Commit changes")

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
            manager = PanoramaManager(
                hostname=PANORAMA_HOST,
                api_key=API_KEY,
                audit_comment=AUDIT_COMMENT,
                commit_changes=COMMIT
            )
        elif not API_KEY and not USERNAME:
            credentails = get_secret(VAULT, vaultpath)
            API_KEY = credentails.get("pano_apikey")
            manager = PanoramaManager(
                hostname=PANORAMA_HOST,
                api_key=API_KEY,
                audit_comment=AUDIT_COMMENT,
                commit_changes=COMMIT
            )
        elif USERNAME:
            if not PASSWORD:
                credentails = get_secret(VAULT, vaultpath)
                PASSWORD = credentails.get(USERNAME)
    
            manager = PanoramaManager(
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

            results = manager.run_operation(OPERATION, cfg_data)
    
            logger.info("Operation results:")
            for obj_name, success in results.items():
                status = "✓" if success else "✗"
                logger.info(f"  {status} {obj_name}")

    
        logger.info("=" * 60)
        logger.info("Operations completed successfully!")
        logger.info("=" * 60)

if __name__ == "__main__":
    main()
