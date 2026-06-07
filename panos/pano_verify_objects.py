#!/usr/bin/env python3
"""
Panorama Object Location Verifier

This script connects to Palo Alto Panorama and verifies whether specified
objects (address objects, address groups, service objects, etc.) exist
in the Shared location or within specific Device Groups.

Requirements:
    pan-os-python (pip install pan-os-python)
"""

import argparse
import sys
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from datetime import datetime

from panos.panorama import Panorama, DeviceGroup
from panos.objects import AddressObject, AddressGroup, ServiceObject, ServiceGroup
from panos.policies import SecurityRule, PostRulebase, PreRulebase


@dataclass
class VerificationResult:
    """Stores the result of an object verification check."""
    object_name: str
    object_value: str
    object_type: str
    location_type: str  # 'Shared' or 'DeviceGroup'
    location_name: str
    exists: bool
    details: Optional[str] = None


class PanoramaObjectVerifier:
    """
    Verifies existence of objects in Panorama Shared or Device Group locations.
    
    This class handles connection to Panorama and provides methods to search
    for various object types across different configuration contexts.
    """
    
    # Supported object types and their corresponding pan-os-python classes
    SUPPORTED_OBJECTS = {
        'address': AddressObject,
        'address-group': AddressGroup,
        'service': ServiceObject,
        'service-group': ServiceGroup,
    }
    
    def __init__(self, hostname: str, username: str=None, password: str=None):
        """
        Initialize the Panorama verifier.
        
        Args:
            hostname: Panorama IP address or hostname
            username: Panorama API username
            password: Panorama API password
            apikey: Panorama API key
        """
        self.hostname = hostname
        self.username = username
        self.password = password
        self.panorama: Optional[Panorama] = None
        self.device_groups: List[DeviceGroup] = []
        
    def connect(self) -> bool:
        """
        Establish connection to Panorama and refresh device groups.
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            self.panorama = Panorama(
                self.hostname,
                self.username,
                self.password
            )
            
            # Get all device groups
            self.device_groups = DeviceGroup.refreshall(self.panorama)
            print(f"✓ Connected to Panorama: {self.hostname}")
            print(f"✓ Found {len(self.device_groups)} Device Group(s)")
            return True
            
        except Exception as e:
            print(f"✗ Failed to connect to Panorama: {e}")
            return False
    
    def _find_object_in_container(self, container, object_name: str, object_value: str,
                                    object_class) -> Optional[Any]:
        """
        Search for an object within a specific container (Shared or DeviceGroup).
        
        Args:
            container: Panorama or DeviceGroup container object
            object_name: Name of the object to find
            object_value: Value of the object to search for
            object_class: pan-os-python class of the object
            
        Returns:
            The object if found, None otherwise
        """
        try:
            objects = object_class.refreshall(container)
            for obj in objects:
                if obj.name == object_name or obj.value == object_value:
                    return obj
        except Exception as e:
            # Silently skip containers that don't support this object type
            pass
        return None
    
    def _search_shared(self, object_name: str, object_value: str, object_type: str) -> bool:
        """
        Search for an object in the Shared location.
        
        Args:
            object_name: Name of the object to search for
            object_value: Value of the object to search for
            object_type: Type of object (e.g., 'address', 'value', 'service')
            
        Returns:
            True if object exists in Shared, False otherwise
        """
        if object_type not in self.SUPPORTED_OBJECTS:
            return False
            
        object_class = self.SUPPORTED_OBJECTS[object_type]
        
        try:
            # Shared objects are directly under Panorama
            obj = self._find_object_in_container(
                self.panorama, object_name, object_value, object_class
            )
            return obj
        except Exception as e:
            print(f"  Warning: Error searching Shared for {object_name}: {e}")
            return False
    
    def _search_device_groups(self, object_name: str, object_value: str, object_type: str) -> List[Dict]:
        """
        Search for an object across all device groups.
        
        Args:
            object_name: Name of the object to search for
            object_value: Value of the object to search for
            object_type: Type of object (e.g., 'address', 'service')
            
        Returns:
            List of dictionaries containing device group locations where object exists
        """
        if object_type not in self.SUPPORTED_OBJECTS:
            return []
            
        object_class = self.SUPPORTED_OBJECTS[object_type]
        found_in = []
        
        for dg in self.device_groups:
            try:
                dg.refresh()
                obj = self._find_object_in_container(dg, object_name, object_value, object_class)
                if obj:
                    found_in.append({
                        'name': dg.name,
                        'object': obj
                    })
            except Exception as e:
                # Skip device groups that cause errors
                continue
                
        return found_in
    
    def verify_object(self, object_name: str, object_value: str, object_type: str) -> VerificationResult:
        """
        Verify if an object exists in Shared or any Device Group.
        
        Args:
            object_name: Name of the object to verify
            object_value: Value of the object to search for
            object_type: Type of object (address, address-group, service, 
                        service-group)
                        
        Returns:
            VerificationResult containing the verification outcome
        """
        if object_type not in self.SUPPORTED_OBJECTS:
            return VerificationResult(
                object_name=object_name,
                object_value=object_value,
                object_type=object_type,
                location_type="Unknown",
                location_name="",
                exists=False,
                details=f"Unsupported object type: {object_type}"
            )
        
        # First check Shared location
        found_obj = self._search_shared(object_name, object_value, object_type)
        if found_obj:
            return VerificationResult(
                object_name=found_obj.name,
                object_value=object_value,
                object_type=object_type,
                location_type="Shared",
                location_name="Shared",
                exists=True,
                details="Object found in Shared configuration"
            )
        
        # Then check all device groups
        found_in_dgs = self._search_device_groups(object_name, object_value, object_type)
        
        if found_in_dgs:
            # Return the first found location (object can exist in multiple)
            location = ", ".join([x.get('name') for x in found_in_dgs])
            obj = ", ".join([x.get('object').name for x in found_in_dgs])
            return VerificationResult(
                object_name=obj,
                object_value=object_value,
                object_type=object_type,
                location_type="DeviceGroup",
                location_name=location,
                exists=True,
                details=f"Object found in Device Group: {location}"
            )
        
        return VerificationResult(
            object_name=object_name,
            object_value=object_value,
            object_type=object_type,
            location_type="None",
            location_name="",
            exists=False,
            details="Object not found in Shared or any Device Group"
        )
    
    def verify_multiple_objects(self, objects: List[Dict]) -> List[VerificationResult]:
        """
        Verify multiple objects.
        
        Args:
            objects: List of dictionaries with 'name' and 'type' keys
                    e.g., [{'name': 'web-server', 'value': '10.1.1.1/32', 'type': 'address'}, ...]
                    
        Returns:
            List of VerificationResult objects
        """
        results = []
        total = len(objects)
        
        for idx, obj_info in enumerate(objects, 1):
            object_name = obj_info.get('name')
            object_value = obj_info.get('value')
            object_type = obj_info.get('type')
            
            if not object_name or not object_value or not object_type:
                results.append(VerificationResult(
                    object_name=object_name or "Unknown",
                    object_value=object_value or "Unknown",
                    object_type=object_type or "Unknown",
                    location_type="Error",
                    location_name="",
                    exists=False,
                    details="Missing name or type in input"
                ))
                continue
            
            print(f"  [{idx}/{total}] Checking: {object_name} ({object_value}) ({object_type})...")
            result = self.verify_object(object_name, object_value, object_type)
            results.append(result)
            
        return results
    
    def list_shared_objects(self, object_type: str = None) -> Dict[str, List[str]]:
        """
        List all objects in Shared location, optionally filtered by type.
        
        Args:
            object_type: Optional object type to filter by
            
        Returns:
            Dictionary mapping object types to lists of object names
        """
        shared_objects = {}
        
        types_to_check = [object_type] if object_type else self.SUPPORTED_OBJECTS.keys()
        
        for obj_type in types_to_check:
            if obj_type not in self.SUPPORTED_OBJECTS:
                continue
                
            object_class = self.SUPPORTED_OBJECTS[obj_type]
            shared_objects[obj_type] = []
            
            try:
                objects = object_class.refreshall(self.panorama)
                shared_objects[obj_type] = [obj.name for obj in objects]
            except Exception:
                shared_objects[obj_type] = []
                
        return shared_objects
    
    def list_device_group_objects(self, device_group_name: str = None, 
                                   object_type: str = None) -> Dict[str, Dict[str, List[str]]]:
        """
        List objects in Device Groups, optionally filtered by group name and type.
        
        Args:
            device_group_name: Optional device group name to filter
            object_type: Optional object type to filter
            
        Returns:
            Nested dictionary: device_group -> object_type -> list of object names
        """
        result = {}
        groups_to_check = [dg for dg in self.device_groups 
                          if not device_group_name or dg.name == device_group_name]
        
        types_to_check = [object_type] if object_type else self.SUPPORTED_OBJECTS.keys()
        
        for dg in groups_to_check:
            try:
                dg.refresh()
                result[dg.name] = {}
                
                for obj_type in types_to_check:
                    if obj_type not in self.SUPPORTED_OBJECTS:
                        continue
                        
                    object_class = self.SUPPORTED_OBJECTS[obj_type]
                    result[dg.name][obj_type] = []
                    
                    try:
                        objects = object_class.refreshall(dg)
                        result[dg.name][obj_type] = [obj.name for obj in objects]
                    except Exception:
                        result[dg.name][obj_type] = []
                        
            except Exception as e:
                result[dg.name] = {'error': str(e)}
                
        return result
    
    def print_report(self, results: List[VerificationResult]) -> None:
        """
        Print a formatted report of verification results.
        
        Args:
            results: List of VerificationResult objects
        """
        print("\n" + "=" * 80)
        print("VERIFICATION REPORT")
        print("=" * 80)
        
        # Separate results by existence
        found = [r for r in results if r.exists]
        not_found = [r for r in results if not r.exists]
        
        # Print found objects
        print(f"\n✓ OBJECTS FOUND ({len(found)}):")
        print("-" * 40)
        for result in found:
            print(f"  • {result.object_name} ({result.object_value}) ({result.object_type})")
            print(f"    Location: {result.location_type}: {result.location_name}")
            print(f"    Details: {result.details}")
            
        # Print not found objects
        print(f"\n✗ OBJECTS NOT FOUND ({len(not_found)}):")
        print("-" * 40)
        for result in not_found:
            print(f"  • {result.object_name} ({result.object_value}) ({result.object_type})")
            print(f"    Details: {result.details}")
            
        print("\n" + "=" * 80)
        print(f"Summary: {len(found)} found, {len(not_found)} not found")
        print("=" * 80)


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Verify existence of objects in Panorama Shared or Device Groups"
    )
    
    # Connection arguments
    parser.add_argument("--hostname", "-H", required=True,
                        help="Panorama hostname or IP address")
    parser.add_argument("--username", "-u", type=str, required=True,
                        help="Panorama API username")
    parser.add_argument("--password", "-p", type=str, required=True,
                        help="Panorama API password")
    
    # Operation mode (either verify or list)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--verify", "-v", nargs=3, action="append",
                       metavar=("NAME", "VALUE", "TYPE"),
                       help="Verify an object (can be used multiple times). "
                            "TYPE can be: address, address-group, service, "
                            "service-group")
    group.add_argument("--verify-file", "-f",
                       help="JSON file containing list of objects to verify")
    group.add_argument("--list-shared", action="store_true",
                       help="List all objects in Shared location")
    group.add_argument("--list-dg", "-l", nargs="?", const="all",
                       help="List objects in Device Groups (optional: specific DG name)")
    
    # Optional filtering for list operations
    parser.add_argument("--type", "-t", choices=["address", "address-group", 
                                                  "service", "service-group"],
                        help="Filter list operations by object type")
    
    return parser.parse_args()


def load_objects_from_file(filepath: str) -> List[Dict]:
    """Load object list from JSON file."""
    import json
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        elif isinstance(data, dict) and 'objects' in data:
            return data['objects']
        else:
            print(f"Error: Invalid JSON format. Expected list or dict with 'objects' key.")
            return []
    except Exception as e:
        print(f"Error loading file: {e}")
        return []


def main():
    """Main entry point for the script."""
    args = parse_arguments()
    
    # Create verifier instance
    verifier = PanoramaObjectVerifier(
        args.hostname,
        args.username,
        args.password
    )
    
    # Connect to Panorama
    if not verifier.connect():
        sys.exit(1)
    
    # Execute requested operation
    if args.verify:
        # Verify multiple objects from command line
        objects = [{'name': name, 'value': value, 'type': obj_type} 
                   for name, value, obj_type in args.verify]
        results = verifier.verify_multiple_objects(objects)
        verifier.print_report(results)
        
    elif args.verify_file:
        # Verify objects from JSON file
        objects = load_objects_from_file(args.verify_file)
        if not objects:
            sys.exit(1)
        results = verifier.verify_multiple_objects(objects)
        verifier.print_report(results)
        
    elif args.list_shared:
        # List Shared objects
        print(f"\nShared Location Objects:")
        print("=" * 50)
        shared_objs = verifier.list_shared_objects(args.type)
        for obj_type, obj_names in shared_objs.items():
            if obj_names:
                print(f"\n{obj_type.upper()} ({len(obj_names)}):")
                for name in obj_names:
                    print(f"  • {name}")
        if not any(shared_objs.values()):
            print("No objects found in Shared location")
            
    elif args.list_dg:
        # List Device Group objects
        dg_name = None if args.list_dg == "all" else args.list_dg
        result = verifier.list_device_group_objects(dg_name, args.type)
        
        print(f"\nDevice Group Objects:")
        print("=" * 50)
        for dg_name, contents in result.items():
            if 'error' in contents:
                print(f"\n{dg_name}: Error - {contents['error']}")
            else:
                has_objects = any(contents.values())
                if has_objects:
                    print(f"\n{dg_name}:")
                    for obj_type, obj_names in contents.items():
                        if obj_names:
                            print(f"  {obj_type.upper()} ({len(obj_names)}):")
                            for name in obj_names:
                                print(f"    • {name}")
                else:
                    print(f"\n{dg_name}: No objects of specified type(s)")


if __name__ == "__main__":
    main()
