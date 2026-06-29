#!/usr/bin/env python3
"""
Script to manage custom URL categories, address objects, and address groups
in a Panorama device group.
"""

import logging
import sys
import json
import os
from pathlib import Path
from typing import List, Optional, Dict, Any, Union
from panos.panorama import Panorama, DeviceGroup
from panos.objects import (
    CustomUrlCategory,
    AddressObject,
    AddressGroup,
    ServiceObject,
    ServiceGroup
)

# Configure logging to see what's happening
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class PanoramaObjectManager:
    """
    A class to manage custom URL categories, address objects, and address groups
    on a Panorama device group.
    """

    def __init__(self, hostname: str, username: str = None, password: str = None,
                 api_key: str = None, device_group: str = "Shared", **kwargs):
        """
        Initialize the Panorama connection.

        Args:
            hostname: Panorama hostname or IP address
            username: Username for authentication (optional if api_key provided)
            password: Password for authentication (optional if api_key provided)
            api_key: API key for authentication (optional)
            device_group: Name of the device group to manage
        """
        self.hostname = hostname
        self.device_group_name = device_group
        self.scope = None

        if api_key:
            self.panorama = Panorama(hostname, api_key=api_key)
        elif username and password:
            self.panorama = Panorama(hostname, api_username=username, api_password=password)

        # Get the device group
        if self.device_group_name != "Shared":
            self.device_group = self._get_device_group()
            if not self.device_group:
                logger.info(f"Error: '{device_group}' does not exist")
                sys.exit(0)

    def _get_device_group(self):
        """Find and return a device group object."""
        device_groups = DeviceGroup.refreshall(self.panorama)

        for dg in device_groups:
            if dg.name == self.device_group_name:
                return dg
        return None

    def _get_existing_object(self, object_type: type, name: str):
        """
        Generic method to check if an object already exists in the device group.

        Args:
            object_type: The PAN-OS object class (AddressObject, AddressGroup, etc.)
            name: Name of the object to find

        Returns:
            Object instance if found, None otherwise
        """
        if self.device_group_name == "Shared":
            objects = object_type.refreshall(self.panorama)
        else:
            self.device_group.refresh()
            objects = object_type.refreshall(self.device_group)
        
        for obj in objects:
            if obj.name == name:
                return obj
        return None

    # ==================== URL CATEGORY METHODS ====================

    def create_or_update_url_category(self, name: str, url_list: List[str],
                                      description: str = None,
                                      category_type: str = "URL List") -> bool:
        """
        Create a new custom URL category or update an existing one.

        Args:
            name: Name of the URL category (max 31 chars)
            url_list: List of URLs or domain patterns
            description: Optional description (max 255 chars)
            category_type: "URL List" or "Category Match"

        Returns:
            True if successful, False otherwise
        """
        try:
            existing = self._get_existing_object(CustomUrlCategory, name)

            if existing:
                logger.info(f"URL Category '{name}' already exists. Updating...")
                existing.url_value = url_list
                if description:
                    existing.description = description
                existing.apply()
                logger.info(f"Successfully updated URL category '{name}'")
            else:
                logger.info(f"URL Category '{name}' does not exist. Creating...")
                new_obj = CustomUrlCategory(
                    name=name,
                    url_value=url_list,
                    description=description,
                    type=category_type
                )
                if self.device_group_name == "Shared":
                    self.panorama.add(new_obj)
                else:
                    self.device_group.add(new_obj)
                new_obj.create()
                logger.info(f"Successfully created URL category '{name}'")

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

    def create_or_update_address_object(self, name: str, ip_address: str = None,
                                        description: str = None,
                                        ip_range: str = None,
                                        subnet: str = None,
                                        fqdn: str = None,
                                        ip_wildcard: str = None) -> bool:
        """
        Create or update an address object.

        Args:
            name: Name of the address object
            ip_address: Single IP address (e.g., "192.168.1.1")
            description: Optional description
            ip_range: IP range (e.g., "192.168.1.1-192.168.1.10")
            subnet: Subnet (e.g., "192.168.1.0/24")
            fqdn: FQDN (e.g., "www.example.com")
            ip_wildcard: Wildcard IP (e.g., "192.168.1.*")

        Note: Provide exactly ONE of ip_address, ip_range, subnet, fqdn, or ip_wildcard

        Returns:
            True if successful, False otherwise
        """
        try:
            # Determine the value type
            if ip_address:
                value_type = "ip-netmask"
                value = ip_address
            elif ip_range:
                value_type = "ip-range"
                value = ip_range
            elif subnet:
                value_type = "ip-netmask"
                value = subnet
            elif fqdn:
                value_type = "fqdn"
                value = fqdn
            elif ip_wildcard:
                value_type = "ip-wildcard"
                value = ip_wildcard
            else:
                raise ValueError("Must provide one of: ip_address, ip_range, subnet, fqdn, or ip_wildcard")

            existing = self._get_existing_object(AddressObject, name)

            if existing:
                logger.info(f"Address Object '{name}' already exists. Updating...")
                existing.type = value_type
                existing.value = value
                if description:
                    existing.description = description
                existing.apply()
                logger.info(f"Successfully updated address object '{name}'")
            else:
                logger.info(f"Address Object '{name}' does not exist. Creating...")
                new_obj = AddressObject(
                    name=name,
                    value=value,
                    type=value_type,
                    description=description
                )
                if self.device_group_name == "Shared":
                    self.panorama.add(new_obj)
                else:
                    self.device_group.add(new_obj)
                new_obj.create()
                logger.info(f"Successfully created address object '{name}'")

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
                if self.device_group_name == "Shared":
                    self.panorama.add(new_obj)
                else:
                    self.device_group.add(new_obj)
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
                if self.device_group_name == "Shared":
                    self.panorama.add(new_obj)
                else:
                    self.device_group.add(new_obj)
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

    def create_or_update_service_object(self, name: str, protocol: str,
                                        destination_port: str,
                                        description: str = None) -> bool:
        """
        Create or update an service object.

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
                logger.info(f"Service Object '{name}' already exists. Updating...")
                existing.protocol = protocol
                existing.destination_port = destination_port
                if description:
                    existing.description = description
                existing.apply()
                logger.info(f"Successfully updated service object '{name}'")
            else:
                logger.info(f"Service Object '{name}' does not exist. Creating...")
                new_obj = ServiceObject(
                    name=name,
                    protocol=protocol,
                    destination_port=destination_port,
                    description=description
                )
                if self.device_group_name == "Shared":
                    self.panorama.add(new_obj)
                else:
                    self.device_group.add(new_obj)
                new_obj.create()
                logger.info(f"Successfully created service object '{name}'")

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
                if self.device_group_name == "Shared":
                    self.panorama.add(new_obj)
                else:
                    self.device_group.add(new_obj)
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

    # ==================== BULK OPERATION METHODS ====================

    def bulk_operate_objects(self, operation: str, objects_config: Dict[str, Any]) -> Dict[str, bool]:
        """
        Create multiple objects in bulk.

        Args:
            operation: Operation mode is either 'create' or 'delete'
            objects_config: Dictionary containing configuration for multiple objects
                Example:
                {
                    "address_objects": [
                        {"name": "web-server", "ip_address": "192.168.1.10"},
                        {"name": "db-server", "ip_address": "192.168.1.20"}
                    ],
                    "address_groups": [
                        {"name": "web-servers", "member_names": ["web-server", "web-server2"]}
                    ],
                    "url_categories": [
                        {"name": "Dev-Sites", "url_list": ["*.dev.local"]}
                    ]
                }

        Returns:
            Dictionary with object names and success status
        """
        results = {}

        try:
            if operation == 'create':
                # Create address objects
                if "address_objects" in objects_config:
                    for addr_obj in objects_config["address_objects"]:
                        name = addr_obj.get("name")
                        if name:
                            # Extract the address type
                            addr_params = {k: v for k, v in addr_obj.items() if k != "name"}
                            success = self.create_or_update_address_object(name, **addr_params)
                            results[f"address_object_{name}"] = success
    
                # Create URL categories
                if "url_categories" in objects_config:
                    for url_cat in objects_config["url_categories"]:
                        name = url_cat.get("name")
                        if name:
                            url_params = {k: v for k, v in url_cat.items() if k != "name"}
                            success = self.create_or_update_url_category(name, **url_params)
                            results[f"url_category_{name}"] = success
    
                # Create address groups
                if "address_groups" in objects_config:
                    for addr_group in objects_config["address_groups"]:
                        name = addr_group.get("name")
                        if name:
                            addr_group_params = {k: v for k, v in addr_group.items() if k != "name"}
                            if "filter_criteria" in addr_group_params:
                                success = self.create_or_update_dynamic_address_group(name, **addr_group_params)
                            else:
                                success = self.create_or_update_static_address_group(name, **addr_group_params)
                            results[f"address_group_{name}"] = success
                
                # Create service objects
                if "service_objects"in objects_config:
                    for serv_obj in objects_config["service_objects"]:
                        name = serv_obj.get("name")
                        if name:
                            serv_params = {k: v for k, v in serv_obj.items() if k != "name"}
                            success = self.create_or_update_service_object(name, **serv_params)
                            results[f"service_object_{name}"] = success

                # Create service groups
                if "service_groups" in objects_config:
                    for serv_group in objects_config["service_groups"]:
                        name = serv_group.get("name")
                        if name:
                            serv_group_params = {k: v for k, v in serv_group.items() if k != "name"}
                            success = self.create_or_update_service_group(name, **serv_group_params)
                            results[f"service_group_{name}"] = success

            elif operation == 'delete':
                # Delete address groups
                if "address_groups" in objects_config:
                    for addr_group in objects_config["address_groups"]:
                        name = addr_group.get("name")
                        if name:
                            success = self.delete_address_group(name)
                            results[f"address_group_{name}"] = success

                # Delete address objects
                if "address_objects" in objects_config:
                    for addr_obj in objects_config["address_objects"]:
                        name = addr_obj.get("name")
                        if name:
                            success = self.delete_address_object(name)
                            results[f"address_object_{name}"] = success
    
                # Delete URL categories
                if "url_categories" in objects_config:
                    for url_cat in objects_config["url_categories"]:
                        name = url_cat.get("name")
                        if name:
                            success = self.delete_url_category(name)
                            results[f"url_category_{name}"] = success

                # Delete service groups
                if "service_groups" in objects_config:
                    for serv_group in objects_config["service_groups"]:
                        name = serv_group.get("name")
                        if name:
                            success = self.delete_service_group(name)
                            results[f"service_group_{name}"] = success

                # Delete service objects
                if "service_objects" in objects_config:
                    for serv_obj in objects_config["service_objects"]:
                        name = serv_obj.get("name")
                        if name:
                            success = self.delete_service_object(name)
                            results[f"service_object_{name}"] = success
    
            return results

        except Exception as e:
            logger.error(f"Error in bulk operation: {e}")
            return results

    def list_objects(self, objects_config) -> Dict[str, List]:
        """
        List objects in the device group.

        Args:
            object_type: Type of objects to list ("address", "url", "group", "all")

        Returns:
            List of dictionaries containing object information
        """
        results = {"success": [], "fail": []}

        try:
            if self.device_group_name == "Shared":
                scope = self.panorama
            else:
                self.device_group.refresh()
                scope = self.device_group
            for object_type, object_value in objects_config.items():
                if object_type == "address_objects":
                    objects = [obj.get('name') for obj in object_value]
                    addresses = AddressObject.refreshall(scope)
                    all_addr = [addr.name for addr in addresses]
                    for addr in addresses:
                        if addr.name in objects:
                            results["success"].append({
                                "type": "address",
                                "name": addr.name,
                                "value": addr.value,
                                "description": addr.description
                            })
                    fail = [f"address_{n}" for n in objects if n not in all_addr]
                    results["fail"].extend(fail)

                if object_type == "url_categories":
                    objects = [obj.get('name') for obj in object_value]
                    url_cats = CustomUrlCategory.refreshall(scope)
                    all_url = [obj.name for obj in url_cats]
                    for url in url_cats:
                        if url.name in objects:
                            results["success"].append({
                                "type": "url_category",
                                "name": url.name,
                                "list": url.url_value,
                                "description": url.description
                            })
                    fail = [f"url_category_{n}" for n in objects if n not in all_url]
                    results["fail"].extend(fail)
    
                if object_type == "address_groups":
                    objects = [obj.get('name') for obj in object_value]
                    addr_groups = AddressGroup.refreshall(scope)
                    all_addr_grp = [grp.name for grp in addr_groups]
                    for addr_grp in addr_groups:
                        if addr_grp.name in objects:
                            if addr_grp.static_value:
                                members = addr_grp.static_value
                            elif addr_grp.dynamic_value:
                                members = addr_grp.dynamic_value
                            results["success"].append({
                                "type": "address_group",
                                "name": addr_grp.name,
                                "members": members,
                                "description": addr_grp.description
                            })
                    fail = [f"address_group_{n}" for n in objects if n not in all_addr_grp]
                    results["fail"].extend(fail)

                if object_type == "service_objects":
                    objects = [obj.get('name') for obj in object_value]
                    services = ServiceObject.refreshall(scope)
                    all_serv = [serv.name for serv in services]
                    for serv in services:
                        if serv.name in objects:
                            results["success"].append({
                                "type": "service",
                                "name": serv.name,
                                "protocol": serv.protocol,
                                "destination_port": serv.destination_port,
                                "description": serv.description
                            })
                    fail = [f"service_{n}" for n in objects if n not in all_serv]
                    results["fail"].extend(fail)

                if object_type == "service_groups":
                    objects = [obj.get('name') for obj in object_value]
                    serv_groups = ServiceGroup.refreshall(scope)
                    all_serv_grp = [grp.name for grp in serv_groups]
                    for serv_grp in serv_groups:
                        if serv_grp.name in objects:
                            results["success"].append({
                                "type": "service_group",
                                "name": serv_grp.name,
                                "value": serv_grp.value
                            })
                    fail = [f"service_group_{n}" for n in objects if n not in all_serv_grp]
                    results["fail"].extend(fail)

            return results

        except Exception as e:
            logger.error(f"Error listing objects: {e}")
            return {}

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
        description="Create/update objects in Panorama Device Groups"
    )
    
    # Connection arguments
    parser.add_argument("--hostname", "-H", required=True,
                        help="Panorama hostname or IP address")
    parser.add_argument("--username", "-u", type=str,
                        help="Panorama admin username")
    parser.add_argument("--file", "-f", type=str, required=True,
                        help="Object configuration file")
    parser.add_argument("--operation", "-o", choices=['create', 'delete', 'list'],
                        default='list', required=True,
                        help="List objects on Panorama")
    
    # Authentication method (either apikey or username/password)
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
    basepath = Path.home() / 'pyenv3.13' / 'panos'
    filepath = f"{basepath}/config_data/{args.file}"

    # Read JSON configuration file
    with open(filepath, 'r', encoding='utf-8-sig') as f:
        configdata = json.load(f)

    # Initialize the manager
    PANORAMA_HOST = args.hostname
    API_KEY = args.apikey
    USERNAME = args.username
    PASSWORD = args.passwd
    DEVICE_GROUP = configdata.get('device_group')
    OPERATION = args.operation
    VAULT = "secrets.bin"
    vaultpath = Path.home() / 'pyenv3.13' / 'secrets'

    if API_KEY:
        manager = PanoramaObjectManager(
            hostname=PANORAMA_HOST,
            api_key=API_KEY,
            device_group=DEVICE_GROUP
        )
    elif USERNAME:
        if not PASSWORD:
            credentails = get_secret(VAULT, vaultpath)
            PASSWORD = credentails.get(USERNAME)

        manager = PanoramaObjectManager(
            hostname=PANORAMA_HOST,
            username=USERNAME,
            password=PASSWORD,
            device_group=DEVICE_GROUP
        )
    else:
        credentails = get_secret(VAULT, vaultpath)
        API_KEY = credentails.get("pano_apikey")
        manager = PanoramaObjectManager(
            hostname=PANORAMA_HOST,
            api_key=API_KEY,
            device_group=DEVICE_GROUP
        )
    
    objects_data = {k: v for k, v in configdata.items() if k != "device_group"}
    if any(OPERATION == op for op in ['create', 'delete']):
        # ==================== CREATE/UPDATE OBJECTS ====================
        logger.info("=" * 60)
        logger.info(f"Creating/deleting objects in '{DEVICE_GROUP}'")
        logger.info("=" * 60)

        results = manager.bulk_operate_objects(OPERATION, objects_data)

        logger.info("Operation results:")
        for obj_name, success in results.items():
            status = "✓" if success else "✗"
            logger.info(f"  {status} {obj_name}")

    elif OPERATION == 'list':
        # ==================== DISPLAY OBJECTS ====================
        logger.info(f"Searching objects in device group '{DEVICE_GROUP}':")
        logger.info("=" * 60)
        output = manager.list_objects(objects_data)

        if output["success"]:
            for obj in output["success"]:
                value = [",".join(map(str, v)) if isinstance(v, list) else v for k, v in obj.items() if k != 'name' and k != 'type' and k != 'description']
                logger.info(f"✓ {obj.get('type')}_{obj.get('name')}")
                logger.info(f"Object value: {(' ').join(value)}")
        if output["fail"]:
            for obj in output["fail"]:
                logger.info(f"✗ {obj}")

    logger.info("=" * 60)
    logger.info("Operations completed successfully!")
    logger.info("=" * 60)

if __name__ == "__main__":
    main()
