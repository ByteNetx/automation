#!/usr/bin/env python3
"""
Script to manage custom URL categories, address objects, address groups,
service objects, service groups, and EDLs in Panorama device groups
using the pan-os-python SDK.
"""

import logging
import sys
import json
import os
from pathlib import Path
from typing import List, Optional, Dict, Any, Union
from enum import Enum
from panos.panorama import Panorama, DeviceGroup
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

    @classmethod
    def from_string(cls, value: str) -> 'OperationType':
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(f"Invalid operation: {value}. Must be 'create', 'delete', or 'list'")

class ObjectType(Enum):
    """Object type"""
    ADDRESS = "AddressObject"
    ADDRESS_GROUP = "AddressGroup"
    SERVICE = "ServiceObject"
    SERVICE_GROUP = "ServiceGroup"
    URL_CATEGORY = "CustomUrlCategory"
    EDL = "Edl"

    @classmethod
    def from_string(cls, value: str) -> 'ObjectType':
        try:
            return cls(value)
        except ValueError:
            raise ValueError(f"Invalid object type: {value}.")


class PanoramaObjectManager:
    """
    A class to manage custom URL categories, address objects, address groups,
    service objects, service groups, and EDLs in Panorama device groups.
    """

    def __init__(self, hostname: str, username: str = None, password: str = None,
                 api_key: str = None, commit_changes: bool=False, **kwargs):
        """
        Initialize the Panorama connection.

        Args:
            hostname: Panorama hostname or IP address
            username: Username for authentication (optional if api_key provided)
            password: Password for authentication (optional if api_key provided)
            api_key: API key for authentication (optional)
            commit_changes: Whether to commit changes
        """
        self.hostname = hostname
        self.username = username
        self.commit_changes = commit_changes
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

    # ==================== URL CATEGORY METHODS ====================

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
            existing = self._get_existing_object(CustomUrlCategory, name)

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
                new_params.updte(url_params)
                print(new_params)

                new_obj = CustomUrlCategory(**new_params)
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
            existing = self._get_existing_object(CustomUrlCategory, name)
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

            existing = self._get_existing_object(AddressObject, name)

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
                new_params.updte(address_params)

                new_obj = AddressObject(**new_params)
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
            existing = self._get_existing_object(AddressObject, name)
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

            existing = self._get_existing_object(AddressGroup, name)

            if existing:
                logger.info(f"Address Group '{name}' already exists. Updating...")
                existing.static_value = member_names
                if description:
                    existing.description = description
                existing.apply()
                logger.info(f"Successfully updated address group '{name}'")
            else:
                logger.info(f"Address Group '{name}' does not exist. Creating...")
                new_obj = AddressGroup(
                    name=name,
                    static_value=member_names,
                    description=description
                )
                self.scope.add(new_obj)
                new_obj.create()
                logger.info(f"Successfully created address group '{name}'")

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
            existing = self._get_existing_object(AddressGroup, name)

            if existing:
                logger.info(f"Dynamic Address Group '{name}' already exists. Updating...")
                existing.dynamic_value = filter_criteria
                if description:
                    existing.description = description
                existing.apply()
                logger.info(f"Successfully updated dynamic address group '{name}'")
            else:
                logger.info(f"Dynamic Address Group '{name}' does not exist. Creating...")
                new_obj = AddressGroup(
                    name=name,
                    dynamic_value=filter_criteria,
                    description=description
                )
                self.scope.add(new_obj)
                new_obj.create()
                logger.info(f"Successfully created dynamic address group '{name}'")

            return True

        except Exception as e:
            logger.error(f"Error managing dynamic address group '{name}': {e}")
            return False

    def delete_address_group(self, name: str) -> bool:
        """Delete an address group (static or dynamic)."""
        try:
            # Try address group first
            existing = self._get_existing_object(AddressGroup, name)
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
            existing = self._get_existing_object(ServiceObject, name)

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

                new_obj = ServiceObject(**new_params)
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
            existing = self._get_existing_object(ServiceObject, name)
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
            existing = self._get_existing_object(ServiceGroup, name)

            if existing:
                logger.info(f"Service Group '{name}' already exists. Updating...")
                existing.value = value
                existing.apply()
                logger.info(f"Successfully updated service group '{name}'")
            else:
                logger.info(f"Service Group '{name}' does not exist. Creating...")
                new_obj = ServiceGroup(
                    name=name,
                    value=value
                )
                self.scope.add(new_obj)
                new_obj.create()
                logger.info(f"Successfully created service group '{name}'")

            return True

        except Exception as e:
            logger.error(f"Error managing service group '{name}': {e}")
            return False

    def delete_service_group(self, name: str) -> bool:
        """Delete an service group."""
        try:
            existing = self._get_existing_object(ServiceGroup, name)
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
            existing = self._get_existing_object(Edl, name)

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

                new_obj = Edl(**new_params)
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
            existing = self._get_existing_object(Edl, name)
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

    # ==================== OBJECT OPERATION METHODS ====================

    def object_operation(self, operation: str, cfg_data: Dict[str, Any]) -> Dict[str, bool]:
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
                # Get the device group
                if device_group_name != "Shared":
                    device_group = self._get_device_group(device_group_name)
                    if not device_group:
                        logger.error(f"Error: '{device_group_name}' does not exist")
                        return results
                    self.scope = device_group
                else:
                    self.scope = self.panorama

                if operation == OperationType.from_string('create').value and object_data:
                    # Create address objects
                    if "address_objects" in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Creating/updating address objects in '{device_group_name}'")
                        logger.info("=" * 60)
                        for addr_obj in object_data["address_objects"]:
                            name = addr_obj.get("name")
                            if name:
                                addr_params = {k: v for k, v in addr_obj.items() if k != "name"}
                                success = self.create_or_update_address_object(name, addr_params)
                                results[f"address_object_{name}"] = success

                    # Create URL categories
                    if "url_categories" in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Creating/updating custom urls in '{device_group_name}'")
                        logger.info("=" * 60)
                        for url_cat in object_data["url_categories"]:
                            name = url_cat.get("name")
                            if name:
                                url_params = {k: v for k, v in url_cat.items() if k != "name"}
                                success = self.create_or_update_url_category(name, url_params)
                                results[f"url_category_{name}"] = success
        
                    # Create address groups
                    if "address_groups" in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Creating/updating address groups in '{device_group_name}'")
                        logger.info("=" * 60)
                        for addr_group in object_data["address_groups"]:
                            name = addr_group.get("name")
                            if name:
                                addr_group_params = {k: v for k, v in addr_group.items() if k != "name"}
                                if "filter_criteria" in addr_group_params:
                                    success = self.create_or_update_dynamic_address_group(name, **addr_group_params)
                                else:
                                    success = self.create_or_update_static_address_group(name, **addr_group_params)
                                results[f"address_group_{name}"] = success
                    
                    # Create service objects
                    if "service_objects"in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Creating/updating service objects in '{device_group_name}'")
                        logger.info("=" * 60)
                        for serv_obj in object_data["service_objects"]:
                            name = serv_obj.get("name")
                            if name:
                                serv_params = {k: v for k, v in serv_obj.items() if k != "name"}
                                success = self.create_or_update_service_object(name, serv_params)
                                results[f"service_object_{name}"] = success
    
                    # Create service groups
                    if "service_groups" in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Creating/updating service groups in '{device_group_name}'")
                        logger.info("=" * 60)
                        for serv_group in object_data["service_groups"]:
                            name = serv_group.get("name")
                            if name:
                                serv_group_params = {k: v for k, v in serv_group.items() if k != "name"}
                                success = self.create_or_update_service_group(name, **serv_group_params)
                                results[f"service_group_{name}"] = success
    
                    # Create external dynamic list
                    if "edls" in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Creating/updating edls in '{device_group_name}'")
                        logger.info("=" * 60)
                        for edl in object_data["edls"]:
                            name = edl.get("name")
                            if name:
                                edl_params = {k: v for k, v in edl.items() if k != "name"}
                                success = self.create_or_update_edl(name, edl_params)
                                results[f"edl_{name}"] = success
    
                elif operation == OperationType.from_string('delete').value and object_data:
                    # Delete address groups
                    if "address_groups" in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Deleting address groups in '{device_group_name}'")
                        logger.info("=" * 60)
                        for addr_group in object_data["address_groups"]:
                            name = addr_group.get("name")
                            if name:
                                success = self.delete_address_group(name)
                                results[f"address_group_{name}"] = success
    
                    # Delete address objects
                    if "address_objects" in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Deleting address objects in '{device_group_name}'")
                        logger.info("=" * 60)
                        for addr_obj in object_data["address_objects"]:
                            name = addr_obj.get("name")
                            if name:
                                success = self.delete_address_object(name)
                                results[f"address_object_{name}"] = success
        
                    # Delete URL categories
                    if "url_categories" in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Deleting custom urls in '{device_group_name}'")
                        logger.info("=" * 60)
                        for url_cat in object_data["url_categories"]:
                            name = url_cat.get("name")
                            if name:
                                success = self.delete_url_category(name)
                                results[f"url_category_{name}"] = success
    
                    # Delete service groups
                    if "service_groups" in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Deleting service groups in '{device_group_name}'")
                        logger.info("=" * 60)
                        for serv_group in object_data["service_groups"]:
                            name = serv_group.get("name")
                            if name:
                                success = self.delete_service_group(name)
                                results[f"service_group_{name}"] = success
    
                    # Delete service objects
                    if "service_objects" in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Deleting service objects in '{device_group_name}'")
                        logger.info("=" * 60)
                        for serv_obj in object_data["service_objects"]:
                            name = serv_obj.get("name")
                            if name:
                                success = self.delete_service_object(name)
                                results[f"service_object_{name}"] = success
    
                    # Delete external dynamic list
                    if "edls" in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Deleting edls in '{device_group_name}'")
                        logger.info("=" * 60)
                        for edl in object_data["edls"]:
                            name = edl.get("name")
                            if name:
                                success = self.delete_edl(name)
                                results[f"edl_{name}"] = success

                elif operation == OperationType.from_string('list').value and object_data:
                    # Search address groups
                    if "address_groups" in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Searching address groups in '{device_group_name}'")
                        logger.info("=" * 60)
                        for addr_group in object_data["address_groups"]:
                            name = addr_group.get("name")
                            if name:
                                existing = self._get_existing_object(AddressGroup, name)
                                if existing:
                                    success = True
                                    logger.info(existing.about())
                                else:
                                    success = False
                                results[f"address_group_{name}"] = success
    
                    # Search address objects
                    if "address_objects" in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Searching address objects in '{device_group_name}'")
                        logger.info("=" * 60)
                        for addr_obj in object_data["address_objects"]:
                            name = addr_obj.get("name")
                            if name:
                                existing = self._get_existing_object(AddressObject, name)
                                if existing:
                                    success = True
                                    logger.info(existing.about())
                                else:
                                    success = False
                                results[f"address_object_{name}"] = success
                                
        
                    # Search URL categories
                    if "url_categories" in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Searching custom urls in '{device_group_name}'")
                        logger.info("=" * 60)
                        for url_cat in object_data["url_categories"]:
                            name = url_cat.get("name")
                            if name:
                                existing = self._get_existing_object(CustomUrlCategory, name)
                                if existing:
                                    success = True
                                    logger.info(existing.about())
                                else:
                                    success = False
                                results[f"url_category_{name}"] = success
    
                    # Search service groups
                    if "service_groups" in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Searching service groups in '{device_group_name}'")
                        logger.info("=" * 60)
                        for serv_group in object_data["service_groups"]:
                            name = serv_group.get("name")
                            if name:
                                existing = self._get_existing_object(ServiceGroup, name)
                                if existing:
                                    success = True
                                    logger.info(existing.about())
                                else:
                                    success = False
                                results[f"service_group_{name}"] = success
    
                    # Search service objects
                    if "service_objects" in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Searching service objects in '{device_group_name}'")
                        logger.info("=" * 60)
                        for serv_obj in object_data["service_objects"]:
                            name = serv_obj.get("name")
                            if name:
                                existing = self._get_existing_object(ServiceObject, name)
                                if existing:
                                    success = True
                                    logger.info(existing.about())
                                else:
                                    success = False
                                results[f"service_object_{name}"] = success
    
                    # Search external dynamic list
                    if "edls" in object_data:
                        logger.info("=" * 60)
                        logger.info(f"Searching edls in '{device_group_name}'")
                        logger.info("=" * 60)
                        for edl in object_data["edls"]:
                            name = edl.get("name")
                            if name:
                                existing = self._get_existing_object(Edl, name)
                                if existing:
                                    success = True
                                    logger.info(existing.about())
                                else:
                                    success = False
                                results[f"edl_{name}"] = success
    
            if any(operation == op for op in [OperationType.from_string('create').value, OperationType.from_string('delete').value]) and results:
                # Commit changes if requested
                if self.commit_changes:
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
        description="Create/delete/list objects in Panorama Device Groups"
    )
    
    # Common arguments
    parser.add_argument("--hostname", "-H", required=True,
                        help="Panorama hostname or IP address")
    parser.add_argument("--username", "-u", type=str,
                        help="Panorama admin username")
    parser.add_argument("--file", "-f", type=str,
                        help="Object configuration JSON file")
    parser.add_argument("--operation", "-o", choices=['create', 'delete', 'list'], 
                        nargs="?", const="list", default='list',
                        help="Operation commands to create/delete/list objects in Panorama. Default to 'list'")
    parser.add_argument("--commit", action='store_true',
                                    help="Enable commit")

    # Search arguments
    search = parser.add_argument_group(title="Search objects")
    search.add_argument("--scope", "-s", type=str, default="Shared",
                        help="Scope to search the object")
    search.add_argument("--type", "-t", type=str,
                        choices=["address","addressgroup","service","servicegroup","url","edl"],
                        help="Type of object to search")
    search.add_argument("--name", "-n", type=str, action="append",
                        help="Name of object to search")

    # Authentication arguments (either apikey or username/password)
    auth = parser.add_mutually_exclusive_group(required=False)
    auth.add_argument("--password", "-p", action=Password, nargs='?', dest='passwd',
                        help="Panorama admin password")
    auth.add_argument("--apikey", "-a", type=str,
                        help="Panorama API key")

    return parser.parse_args()

def get_secret(vault, vaultpath):
    from encryption import CredentialManager
    manager = CredentialManager(vault, vaultpath)
    credentails = manager.decrypt()
    return credentails

def main():
    """
    Main function demonstrating how to use the PanoramaObjectManager class.
    """

    args = parse_arguments()
    basePath = Path.home() / 'pyenv3.9' / 'panos' / 'pano_project'
    filepath = f"{basePath}/config/{args.file}"

    PANORAMA_HOST = args.hostname
    API_KEY = args.apikey
    USERNAME = args.username
    PASSWORD = args.passwd
    OPERATION = args.operation
    COMMIT = args.commit
    VAULT = "panos_secrets.bin"
    vaultpath = Path.home() / 'pyenv3.9' / 'secrets'
    objects_data = {}

    # Get object data
    if os.path.isfile(filepath):
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
        objects_data = {k: v for k, v in data.items() if v}
    elif all(a for a in [args.scope, args.type, args.name]):
        DEVICE_GROUP = args.scope
        OPERATION = 'list'
        if args.type == 'address':
            obj_type = "address_objects"
        elif args.type == 'addressgroup':
            obj_type = "address_groups"
        elif args.type == 'service':
            obj_type = "service_objects"
        elif args.type == 'servicegroup':
            obj_type = "service_groups"
        elif args.type == 'url':
            obj_type = "url_categories"
        elif args.type == 'edl':
            obj_type = "edls"
        objects_data = {DEVICE_GROUP: {obj_type: [{"name": n} for n in args.name]}}
    else:
        logger.info("Error: Objects must be provided")
        sys.exit(0)

    if objects_data:
        # Initialize the manager
        if API_KEY:
            manager = PanoramaObjectManager(
                hostname=PANORAMA_HOST,
                api_key=API_KEY,
                commit_changes=COMMIT
            )
        elif not API_KEY and not USERNAME:
            credentails = get_secret(VAULT, vaultpath)
            API_KEY = credentails.get("pano_apikey")
            manager = PanoramaObjectManager(
                hostname=PANORAMA_HOST,
                api_key=API_KEY,
                commit_changes=COMMIT
            )
        elif USERNAME:
            if not PASSWORD:
                credentails = get_secret(VAULT, vaultpath)
                PASSWORD = credentails.get(USERNAME)
    
            manager = PanoramaObjectManager(
                hostname=PANORAMA_HOST,
                username=USERNAME,
                password=PASSWORD,
                commit_changes=COMMIT
            )
        else:
            logger.error("Missing parameters required to connect Panorama")
            sys.exit()
    
        if any(OPERATION == op for op in ['create', 'delete', 'list']):
            # ==================== OBJECT OPERATION ====================
    
            results = manager.object_operation(OPERATION, objects_data)
    
            logger.info("Operation results:")
            for obj_name, success in results.items():
                status = "✓" if success else "✗"
                logger.info(f"  {status} {obj_name}")
    
        logger.info("=" * 60)
        logger.info("Operations completed successfully!")
        logger.info("=" * 60)

if __name__ == "__main__":
    main()
