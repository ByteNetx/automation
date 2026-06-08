#!/usr/bin/env python3
"""
Panorama Object Discovery and Value Verification

This script connects to Palo Alto Panorama and can:
1. Verify if an object NAME exists in Shared or Device Groups
2. Search for objects containing a specific VALUE (IP, subnet, FQDN, port, etc.)
3. Find where a particular IP/port/service is being used

Requirements:
    pan-os-python (pip install pan-os-python)
    ipaddress (built-in)
"""

import argparse
import sys
import re
from typing import List, Dict, Optional, Any, Union, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_address, ip_network, ip_interface, IPv4Address, IPv6Address

from panos.panorama import Panorama, DeviceGroup
from panos.objects import (
    AddressObject, AddressGroup, ServiceObject, 
    ServiceGroup, Tag, ApplicationObject
)
from panos.policies import SecurityRule, NatRule, PostRulebase, PreRulebase
from panos.network import Interface


@dataclass
class SearchResult:
    """Stores the result of a search operation."""
    search_term: str
    search_type: str  # 'name' or 'value'
    found_objects: List[Dict] = field(default_factory=list)
    
    def add_result(self, object_name: str, object_type: str, location_type: str, 
                   location_name: str, matched_field: str, matched_value: str = None):
        """Add a found object to the results."""
        self.found_objects.append({
            'object_name': object_name,
            'object_type': object_type,
            'location_type': location_type,
            'location_name': location_name,
            'matched_field': matched_field,
            'matched_value': matched_value
        })
    
    @property
    def count(self) -> int:
        return len(self.found_objects)


class PanoramaObjectSearcher:
    """
    Search for objects in Panorama by name or by value.
    
    Can search for:
    - Object names (exact or partial match)
    - IP addresses/subnets in Address Objects
    - FQDN values in Address Objects
    - Port numbers in Service Objects
    - Protocol values in Service Objects
    - Tag values
    - Object references in policies
    """
    
    def __init__(self, hostname: str, username: str, password: str):
        """
        Initialize the Panorama searcher.
        
        Args:
            hostname: Panorama IP address or hostname
            username: Panorama API username
            password: Panorama API password
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
            self.device_groups = DeviceGroup.refreshall(self.panorama)
            print(f"✓ Connected to Panorama: {self.hostname}")
            print(f"✓ Found {len(self.device_groups)} Device Group(s)")
            return True
        except Exception as e:
            print(f"✗ Failed to connect to Panorama: {e}")
            return False
    
    def search_address_objects_by_value(self, container, search_value: str) -> List[Dict]:
        """
        Search address objects for matching IP, subnet, or FQDN.
        
        Args:
            container: Panorama or DeviceGroup object
            search_value: IP address, subnet (CIDR), or FQDN to search for
            
        Returns:
            List of matching address objects with details
        """
        matches = []
        try:
            address_objects = AddressObject.refreshall(container)
            
            for addr_obj in address_objects:
                matched_field = None
                matched_value = None
                
                # Check IPv4/IPv6 address
                if hasattr(addr_obj, 'value') and addr_obj.value:
                    if self._ip_matches(search_value, addr_obj.value):
                        matched_field = "value"
                        matched_value = addr_obj.value
                
                # Check FQDN
                elif hasattr(addr_obj, 'fqdn') and addr_obj.fqdn:
                    if self._fqdn_matches(search_value, addr_obj.fqdn):
                        matched_field = "fqdn"
                        matched_value = addr_obj.fqdn
                
                # Check IP range
                elif hasattr(addr_obj, 'ip_range') and addr_obj.ip_range:
                    if self._ip_range_matches(search_value, addr_obj.ip_range):
                        matched_field = "ip_range"
                        matched_value = addr_obj.ip_range
                
                if matched_field:
                    matches.append({
                        'name': addr_obj.name,
                        'type': 'address',
                        'matched_field': matched_field,
                        'matched_value': matched_value,
                        'full_object': addr_obj
                    })
        except Exception as e:
            pass
            
        return matches
    
    def search_service_objects_by_value(self, container, search_value: str) -> List[Dict]:
        """
        Search service objects for matching port, protocol, or port range.
        
        Args:
            container: Panorama or DeviceGroup object
            search_value: Port number, protocol, or service name to search
            
        Returns:
            List of matching service objects
        """
        matches = []
        try:
            service_objects = ServiceObject.refreshall(container)
            
            for svc_obj in service_objects:
                matched_fields = []
                
                # Check destination port
                if hasattr(svc_obj, 'destination_port') and svc_obj.destination_port:
                    if self._port_matches(search_value, svc_obj.destination_port):
                        matched_fields.append(('destination_port', svc_obj.destination_port))
                
                # Check source port
                if hasattr(svc_obj, 'source_port') and svc_obj.source_port:
                    if self._port_matches(search_value, svc_obj.source_port):
                        matched_fields.append(('source_port', svc_obj.source_port))
                
                # Check protocol
                if hasattr(svc_obj, 'protocol') and svc_obj.protocol:
                    if search_value.lower() == svc_obj.protocol.lower():
                        matched_fields.append(('protocol', svc_obj.protocol))
                
                # Check port range
                if hasattr(svc_obj, 'destination_port') and svc_obj.destination_port:
                    if '-' in search_value and self._in_port_range(search_value, svc_obj.destination_port):
                        matched_fields.append(('dest_port_range', svc_obj.destination_port))
                
                for field, value in matched_fields:
                    matches.append({
                        'name': svc_obj.name,
                        'type': 'service',
                        'matched_field': field,
                        'matched_value': value,
                        'full_object': svc_obj
                    })
        except Exception as e:
            pass
            
        return matches
    
    def search_tag_objects_by_value(self, container, search_value: str) -> List[Dict]:
        """
        Search tag objects for matching tag color or comment.
        
        Args:
            container: Panorama or DeviceGroup object
            search_value: Tag name, color, or comment to search
            
        Returns:
            List of matching tag objects
        """
        matches = []
        try:
            tag_objects = Tag.refreshall(container)
            
            for tag_obj in tag_objects:
                matched_field = None
                matched_value = None
                
                # Check tag name
                if search_value.lower() in tag_obj.name.lower():
                    matched_field = "name"
                    matched_value = tag_obj.name
                
                # Check tag color
                elif hasattr(tag_obj, 'color') and tag_obj.color:
                    if search_value.lower() in tag_obj.color.lower():
                        matched_field = "color"
                        matched_value = tag_obj.color
                
                if matched_field:
                    matches.append({
                        'name': tag_obj.name,
                        'type': 'tag',
                        'matched_field': matched_field,
                        'matched_value': matched_value,
                        'full_object': tag_obj
                    })
        except Exception as e:
            pass
            
        return matches
    
    def search_address_groups_by_member(self, container, search_value: str) -> List[Dict]:
        """
        Search address groups that contain a specific address object.
        
        Args:
            container: Panorama or DeviceGroup object
            search_value: Address object name or value to search for in groups
            
        Returns:
            List of address groups containing the search value
        """
        matches = []
        try:
            address_groups = AddressGroup.refreshall(container)
            
            for group in address_groups:
                if hasattr(group, 'static_value') and group.static_value:
                    for member in group.static_value:
                        if search_value.lower() == member.lower():
                            matches.append({
                                'name': group.name,
                                'type': 'address-group',
                                'matched_field': 'static_value',
                                'matched_value': member,
                                'full_object': group
                            })
                            break
        except Exception as e:
            pass
            
        return matches
    
    def search_service_groups_by_member(self, container, search_value: str) -> List[Dict]:
        """
        Search service groups that contain a specific service object.
        
        Args:
            container: Panorama or DeviceGroup object
            search_value: Service object name to search for in groups
            
        Returns:
            List of service groups containing the search value
        """
        matches = []
        try:
            service_groups = ServiceGroup.refreshall(container)
            
            for group in service_groups:
                if hasattr(group, 'value') and group.value:
                    for member in group.value:
                        if search_value.lower() == member.lower():
                            matches.append({
                                'name': group.name,
                                'type': 'service-group',
                                'matched_field': 'members',
                                'matched_value': member,
                                'full_object': group
                            })
                            break
        except Exception as e:
            pass
            
        return matches
    
    def search_policies_by_reference(self, container, search_value: str) -> List[Dict]:
        """
        Search security and NAT policies that reference a specific object.
        
        Args:
            container: Panorama or DeviceGroup container (Panorama or DG)
            search_value: Object name or value to search in policies
            
        Returns:
            List of policies referencing the search value
        """
        matches = []
        
        # Check pre-rules (rulebase)
        for rulebase in [PreRulebase, PostRulebase]:
            try:
                if hasattr(container, rulebase.__name__):
                    rulebase_obj = getattr(container, rulebase.__name__)
                    if rulebase_obj:
                        rules = SecurityRule.refreshall(rulebase_obj)
                        
                        for rule in rules:
                            matched_fields = []
                            
                            # Check source addresses
                            if hasattr(rule, 'source') and rule.source:
                                for src in rule.source:
                                    if search_value.lower() == src.lower():
                                        matched_fields.append(('source', src))
                            
                            # Check destination addresses
                            if hasattr(rule, 'destination') and rule.destination:
                                for dst in rule.destination:
                                    if search_value.lower() == dst.lower():
                                        matched_fields.append(('destination', dst))
                            
                            # Check services/applications
                            if hasattr(rule, 'service') and rule.service:
                                if search_value.lower() == rule.service.lower():
                                    matched_fields.append(('service', rule.service))
                            
                            if hasattr(rule, 'application') and rule.application:
                                for app in rule.application:
                                    if search_value.lower() == app.lower():
                                        matched_fields.append(('application', app))
                            
                            for field, value in matched_fields:
                                matches.append({
                                    'name': rule.name,
                                    'type': 'security-rule',
                                    'matched_field': field,
                                    'matched_value': value,
                                    'full_object': rule
                                })
            except Exception:
                pass
        
        # Check NAT rules
        try:
            nat_rules = NatRule.refreshall(container)
            for rule in nat_rules:
                matched_fields = []
                
                if hasattr(rule, 'source_addresses') and rule.source_addresses:
                    for src in rule.source_addresses:
                        if search_value.lower() == src.lower():
                            matched_fields.append(('source_addresses', src))
                
                if hasattr(rule, 'destination_addresses') and rule.destination_addresses:
                    for dst in rule.destination_addresses:
                        if search_value.lower() == dst.lower():
                            matched_fields.append(('destination_addresses', dst))
                
                if hasattr(rule, 'source_translation_type') and rule.source_translation_type:
                    if search_value.lower() in str(rule.source_translation_type).lower():
                        matched_fields.append(('source_translation_type', rule.source_translation_type))
                
                for field, value in matched_fields:
                    matches.append({
                        'name': rule.name,
                        'type': 'nat-rule',
                        'matched_field': field,
                        'matched_value': value,
                        'full_object': rule
                    })
        except Exception:
            pass
            
        return matches
    
    def search_by_name(self, search_name: str, object_type: str = None, 
                       exact_match: bool = True) -> SearchResult:
        """
        Search for objects by name.
        
        Args:
            search_name: Name to search for (can include wildcard *)
            object_type: Optional specific object type to search
            exact_match: If True, search for exact name; if False, partial match
            
        Returns:
            SearchResult object containing all matches
        """
        result = SearchResult(search_name, 'name')
        
        # Determine which object types to search
        if object_type:
            types_to_search = [object_type]
        else:
            types_to_search = ['address', 'address-group', 'service', 
                              'service-group', 'tag', 'security-rule', 'nat-rule']
        
        # Search in Shared
        for obj_type in types_to_search:
            matches = self._search_by_name_in_container(
                self.panorama, search_name, obj_type, 'Shared', 'Shared', exact_match
            )
            for match in matches:
                result.add_result(**match)
        
        # Search in Device Groups
        for dg in self.device_groups:
            try:
                dg.refresh()
                for obj_type in types_to_search:
                    matches = self._search_by_name_in_container(
                        dg, search_name, obj_type, 'DeviceGroup', dg.name, exact_match
                    )
                    for match in matches:
                        result.add_result(**match)
            except Exception:
                continue
        
        return result
    
    def _search_by_name_in_container(self, container, search_name: str, 
                                      object_type: str, location_type: str, 
                                      location_name: str, exact_match: bool) -> List[Dict]:
        """Helper method to search for objects by name in a specific container."""
        matches = []
        
        try:
            if object_type == 'address':
                objects = AddressObject.refreshall(container)
            elif object_type == 'address-group':
                objects = AddressGroup.refreshall(container)
            elif object_type == 'service':
                objects = ServiceObject.refreshall(container)
            elif object_type == 'service-group':
                objects = ServiceGroup.refreshall(container)
            elif object_type == 'tag':
                objects = Tag.refreshall(container)
            elif object_type == 'security-rule':
                objects = SecurityRule.refreshall(container)
            elif object_type == 'nat-rule':
                objects = NatRule.refreshall(container)
            else:
                return []
            
            for obj in objects:
                obj_name = getattr(obj, 'name', '')
                if exact_match:
                    if obj_name == search_name:
                        matches.append({
                            'object_name': obj_name,
                            'object_type': object_type,
                            'location_type': location_type,
                            'location_name': location_name,
                            'matched_field': 'name',
                            'matched_value': obj_name
                        })
                else:
                    if search_name.lower() in obj_name.lower():
                        matches.append({
                            'object_name': obj_name,
                            'object_type': object_type,
                            'location_type': location_type,
                            'location_name': location_name,
                            'matched_field': 'name',
                            'matched_value': obj_name
                        })
        except Exception:
            pass
            
        return matches
    
    def search_by_value(self, search_value: str,
                        object_type: str = None, include_policies: bool = True) -> SearchResult:
        """
        Search for objects containing a specific value (IP, port, FQDN, etc.).
        
        Args:
            search_value: Value to search for (IP address, subnet, port, FQDN)
            include_policies: Whether to also search in policy references
            
        Returns:
            SearchResult object containing all matches
        """
        result = SearchResult(search_value, 'value')
        
        # Helper to search in a container
        def search_container(container, obj_type, location_type, location_name):
            # Search address objects
            if obj_type == 'address':
                for match in self.search_address_objects_by_value(container, search_value):
                    result.add_result(
                        object_name=match['name'],
                        object_type=match['type'],
                        location_type=location_type,
                        location_name=location_name,
                        matched_field=match['matched_field'],
                        matched_value=match['matched_value']
                    )
            
            # Search service objects
            if obj_type == 'service':
                for match in self.search_service_objects_by_value(container, search_value):
                    result.add_result(
                        object_name=match['name'],
                        object_type=match['type'],
                        location_type=location_type,
                        location_name=location_name,
                        matched_field=match['matched_field'],
                        matched_value=match['matched_value']
                    )
            
            # Search address groups (by member name)
            if obj_type == 'address-group':
                for match in self.search_address_groups_by_member(container, search_value):
                    result.add_result(
                        object_name=match['name'],
                        object_type=match['type'],
                        location_type=location_type,
                        location_name=location_name,
                        matched_field=match['matched_field'],
                        matched_value=match['matched_value']
                    )
            
            # Search service groups (by member name)
            if obj_type == 'service-group':
                for match in self.search_service_groups_by_member(container, search_value):
                    result.add_result(
                        object_name=match['name'],
                        object_type=match['type'],
                        location_type=location_type,
                        location_name=location_name,
                        matched_field=match['matched_field'],
                        matched_value=match['matched_value']
                    )
            
            # Search tags
            if obj_type == 'tag':
                for match in self.search_tag_objects_by_value(container, search_value):
                    result.add_result(
                        object_name=match['name'],
                        object_type=match['type'],
                        location_type=location_type,
                        location_name=location_name,
                        matched_field=match['matched_field'],
                        matched_value=match['matched_value']
                    )
            
            # Search policies
            if include_policies:
                for match in self.search_policies_by_reference(container, search_value):
                    result.add_result(
                        object_name=match['name'],
                        object_type=match['type'],
                        location_type=location_type,
                        location_name=location_name,
                        matched_field=match['matched_field'],
                        matched_value=match['matched_value']
                    )
        
        if object_type:
            types_to_search = [object_type]
        else:
            types_to_search = ['address', 'address-group', 'service', 
                              'service-group', 'tag']
        # Search in Shared
        for obj_type in types_to_search:
            search_container(self.panorama, obj_type, 'Shared', 'Shared')
        
        # Search in Device Groups
        for obj_type in types_to_search:
            for dg in self.device_groups:
                try:
                    dg.refresh()
                    search_container(dg, obj_type, 'DeviceGroup', dg.name)
                except Exception:
                    continue
        
        return result
    
    def _ip_matches(self, search_value: str, object_value: str) -> bool:
        """Check if search value matches an IP address or subnet."""
        try:
            # Exact match
            if search_value == object_value:
                return True

            # Check if IP is within subnet
            if '/' in object_value:  # Object is a subnet
                try:
                    network = ip_network(object_value, strict=False)
                    search_ip = ip_address(search_value)
                    return search_ip in network
                except:
                    pass
            
            # Check if subnet is within larger subnet
            if '/' in search_value:  # Searching for a subnet
                try:
                    search_network = ip_network(search_value, strict=False)
                    obj_ip = ip_address(object_value)
                    return obj_ip in search_network
                except:
                    pass
            
            # Check wildcard matches (e.g., 192.168.*)
            if '*' in search_value:
                pattern = search_value.replace('.', r'\.').replace('*', '.*')
                if re.match(pattern, object_value):
                    return True
            
            return False
        except:
            return search_value.lower() in object_value.lower()
    
    def _fqdn_matches(self, search_value: str, fqdn_value: str) -> bool:
        """Check if search value matches an FQDN."""
        search_lower = search_value.lower()
        fqdn_lower = fqdn_value.lower()
        
        # Exact match
        if search_lower == fqdn_lower:
            return True
        
        # Wildcard match
        if '*' in search_value:
            pattern = search_value.replace('.', r'\.').replace('*', '.*')
            if re.match(pattern, fqdn_lower):
                return True
        
        # Partial match (contains)
        if search_lower in fqdn_lower:
            return True
        
        return False
    
    def _ip_range_matches(self, search_value: str, ip_range: str) -> bool:
        """Check if search value matches an IP range."""
        if '-' in ip_range:
            try:
                start_ip, end_ip = map(str, search_value.split('-'))
                start, end = map(str, ip_range.split('-'))
                return ip_address(start.strip()) <= ip_address(start_ip.strip()) and ip_address(end_ip.strip()) <= ip_address(end.strip())
            except:
                pass
        return search_value in ip_range
    
    def _port_matches(self, search_value: str, port_value: str) -> bool:
        """Check if search value matches a port number."""
        try:
            if '-' in port_value:
                return search_value == port_value
            else:
                return int(search_value) == int(port_value)
        except:
            return False
    
    def _in_port_range(self, search_value: str, port_range: str) -> bool:
        """Check if a port falls within a port range."""
        try:
            start_port, end_port = map(int, search_value.split('-'))
            if '-' in port_range:
                start, end = map(int, port_range.split('-'))
                return start <= start_port and end_port <= end
        except:
            return False
    
    def print_search_results(self, result: SearchResult):
        """Pretty print search results."""
        print("\n" + "=" * 80)
        print(f"SEARCH RESULTS: {result.search_type.upper()} = '{result.search_term}'")
        print("=" * 80)
        
        if result.count == 0:
            print("\n❌ No matching objects found.\n")
            return
        
        print(f"\n✅ Found {result.count} match(es):\n")
        
        # Group by location and type
        by_location = {}
        for obj in result.found_objects:
            loc_key = f"{obj['location_type']}: {obj['location_name']}"
            if loc_key not in by_location:
                by_location[loc_key] = []
            by_location[loc_key].append(obj)
        
        for location, objects in by_location.items():
            print(f"📍 {location}")
            print("-" * 40)
            
            # Group by object type
            by_type = {}
            for obj in objects:
                obj_type = obj['object_type'].upper()
                if obj_type not in by_type:
                    by_type[obj_type] = []
                by_type[obj_type].append(obj)
            
            for obj_type, type_objects in by_type.items():
                print(f"\n  📦 {obj_type}:")
                for obj in type_objects:
                    print(f"    • {obj['object_name']}")
                    print(f"      - Matched field: {obj['matched_field']} = {obj['matched_value']}")
        
        print("\n" + "=" * 80)


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Search Panorama for objects by name or value"
    )
    
    # Connection arguments
    parser.add_argument("--hostname", "-H", required=True,
                        help="Panorama hostname or IP address")
    parser.add_argument("--username", "-u", required=True,
                        help="Panorama API username")
    parser.add_argument("--password", "-p", required=True,
                        help="Panorama API password")
    
    # Search arguments
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--search-name", "-n", 
                       help="Search for object by exact name")
    group.add_argument("--search-name-partial", "-np",
                       help="Search for object by partial name (contains)")
    group.add_argument("--search-value", "-v",
                       help="Search for value (IP, port, FQDN, etc.)")
    
    # Optional filters
    parser.add_argument("--type", "-t", 
                        choices=["address", "address-group", "service", 
                                "service-group", "tag", "security-rule", "nat-rule"],
                        help="Filter search by object type")
    parser.add_argument("--no-policies", action="store_true",
                        help="Exclude policy references from value search")
    
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_arguments()
    
    # Create searcher instance
    searcher = PanoramaObjectSearcher(
        args.hostname,
        args.username,
        args.password
    )
    
    # Connect to Panorama
    if not searcher.connect():
        sys.exit(1)
    
    # Execute search
    if args.search_name:
        result = searcher.search_by_name(args.search_name, args.type, exact_match=True)
    elif args.search_name_partial:
        result = searcher.search_by_name(args.search_name_partial, args.type, exact_match=False)
    elif args.search_value:
        result = searcher.search_by_value(args.search_value, args.type, not args.no_policies)
    else:
        print("Error: No search specified")
        sys.exit(1)
    
    # Print results
    searcher.print_search_results(result)


if __name__ == "__main__":
    main()
