#!/usr/bin/env python3
"""
Panorama Object Existence Verifier
Verifies if objects exist in Shared context or Device Groups on Palo Alto Panorama
"""

import json
import argparse
import sys
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from colorama import Fore, Back, Style, init

try:
    from panos.panorama import Panorama, DeviceGroup
    from panos.objects import AddressObject, AddressGroup, ServiceObject, ServiceGroup
    from panos.policies import PreRulebase, PostRulebase, SecurityRule
except ImportError:
    print("Error: pan-os-python not installed. Run: pip install pan-os-python")
    sys.exit(1)

init(autoreset=True)


class PanoramaObjectExistenceVerifier:
    """
    Verify if objects exist in Shared context or Device Groups on Panorama
    """
    
    def __init__(self, hostname: str, username: str = None, password: str = None, api_key: str = None):
        """
        Initialize the Panorama verifier
        
        Args:
            hostname: Panorama IP address or hostname
            username: Username for authentication
            password: Password for authentication
            api_key: API key for authentication
        """
        self.hostname = hostname
        self.panorama = None
        self.device_groups_cache = {}
        
        # Establish connection
        try:
            if api_key:
                self.panorama = Panorama(hostname, api_key=api_key)
            elif username and password:
                self.panorama = Panorama(hostname, username, password)
            else:
                raise ValueError("Either (username/password) or api_key must be provided")
            
            # Test connection and refresh
            self.panorama.refresh()
            print(Fore.GREEN + f"[+] Connected to Panorama: {hostname}" + Fore.RESET)
            
        except Exception as e:
            print(Fore.RED + f"[-] Failed to connect: {e}" + Fore.RESET)
            raise
    
    def get_all_device_groups(self) -> List[DeviceGroup]:
        """Retrieve all device groups from Panorama"""
        try:
            device_groups = DeviceGroup.refreshall(self.panorama)
            return device_groups
        except Exception as e:
            print(Fore.RED + f"[-] Error retrieving device groups: {e}" + Fore.RESET)
            return []
    
    def check_address_object(self, object_name: str, device_group: DeviceGroup = None) -> Dict[str, Any]:
        """
        Check if an address object exists
        
        Args:
            object_name: Name of the address object
            device_group: DeviceGroup object (None for shared context)
            
        Returns:
            Dictionary with existence status and details
        """
        result = {
            "object_type": "address_object",
            "object_name": object_name,
            "exists": False,
            "location": None,
            "details": None,
            "error": None
        }
        
        try:
            if device_group:
                # Check in device group
                objects = AddressObject.refreshall(device_group)
                location_prefix = f"device_group:{device_group.name}"
            else:
                # Check in shared context
                objects = AddressObject.refreshall(self.panorama)
                location_prefix = "shared"
            
            for obj in objects:
                if obj.name == object_name:
                    result["exists"] = True
                    result["location"] = location_prefix
                    result["details"] = {
                        "type": obj.type,
                        "value": obj.value,
                        "description": obj.description or "",
                        "tags": obj.tag or []
                    }
                    break
                    
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def check_address_group(self, group_name: str, device_group: DeviceGroup = None) -> Dict[str, Any]:
        """
        Check if an address group exists
        
        Args:
            group_name: Name of the address group
            device_group: DeviceGroup object (None for shared context)
            
        Returns:
            Dictionary with existence status and details
        """
        result = {
            "object_type": "address_group",
            "object_name": group_name,
            "exists": False,
            "location": None,
            "details": None,
            "error": None
        }
        
        try:
            if device_group:
                groups = AddressGroup.refreshall(device_group)
                location_prefix = f"device_group:{device_group.name}"
            else:
                groups = AddressGroup.refreshall(self.panorama)
                location_prefix = "shared"
            
            for group in groups:
                if group.name == group_name:
                    result["exists"] = True
                    result["location"] = location_prefix
                    result["details"] = {
                        "type": "static" if group.static_value else "dynamic" if group.dynamic_value else "unknown",
                        "members": group.static_value if group.static_value else group.dynamic_value,
                        "member_count": len(group.static_value) if group.static_value else (1 if group.dynamic_value else 0),
                        "description": group.description or "",
                        "tags": group.tag or []
                    }
                    break
                    
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def check_service_object(self, object_name: str, device_group: DeviceGroup = None) -> Dict[str, Any]:
        """
        Check if a service object exists
        
        Args:
            object_name: Name of the service object
            device_group: DeviceGroup object (None for shared context)
            
        Returns:
            Dictionary with existence status and details
        """
        result = {
            "object_type": "service_object",
            "object_name": object_name,
            "exists": False,
            "location": None,
            "details": None,
            "error": None
        }
        
        try:
            if device_group:
                objects = ServiceObject.refreshall(device_group)
                location_prefix = f"device_group:{device_group.name}"
            else:
                objects = ServiceObject.refreshall(self.panorama)
                location_prefix = "shared"
            
            for obj in objects:
                if obj.name == object_name:
                    result["exists"] = True
                    result["location"] = location_prefix
                    result["details"] = {
                        "protocol": obj.protocol,
                        "port": obj.port,
                        "source_port": getattr(obj, 'source_port', None),
                        "description": obj.description or "",
                        "tags": obj.tag or []
                    }
                    break
                    
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def check_service_group(self, group_name: str, device_group: DeviceGroup = None) -> Dict[str, Any]:
        """
        Check if a service group exists
        
        Args:
            group_name: Name of the service group
            device_group: DeviceGroup object (None for shared context)
            
        Returns:
            Dictionary with existence status and details
        """
        result = {
            "object_type": "service_group",
            "object_name": group_name,
            "exists": False,
            "location": None,
            "details": None,
            "error": None
        }
        
        try:
            if device_group:
                groups = ServiceGroup.refreshall(device_group)
                location_prefix = f"device_group:{device_group.name}"
            else:
                groups = ServiceGroup.refreshall(self.panorama)
                location_prefix = "shared"
            
            for group in groups:
                if group.name == group_name:
                    result["exists"] = True
                    result["location"] = location_prefix
                    result["details"] = {
                        "members": group.static_value,
                        "member_count": len(group.static_value) if group.static_value else 0,
                        "description": group.description or "",
                        "tags": group.tag or []
                    }
                    break
                    
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def check_security_rule(self, rule_name: str, device_group: DeviceGroup, rulebase_type: str = "pre") -> Dict[str, Any]:
        """
        Check if a security rule exists in a device group's rulebase
        
        Args:
            rule_name: Name of the security rule
            device_group: DeviceGroup object
            rulebase_type: "pre" or "post"
            
        Returns:
            Dictionary with existence status and details
        """
        result = {
            "object_type": f"security_rule_{rulebase_type}",
            "object_name": rule_name,
            "exists": False,
            "location": None,
            "details": None,
            "error": None
        }
        
        try:
            if rulebase_type.lower() == "pre":
                rulebase = PreRulebase()
            else:
                rulebase = PostRulebase()
            
            device_group.add(rulebase)
            rules = SecurityRule.refreshall(rulebase)
            
            for rule in rules:
                if rule.name == rule_name:
                    result["exists"] = True
                    result["location"] = f"device_group:{device_group.name}:{rulebase_type}-rulebase"
                    result["details"] = {
                        "action": rule.action,
                        "from_zone": rule.fromzone,
                        "to_zone": rule.tozone,
                        "source": rule.source[:3] if rule.source and len(rule.source) > 3 else rule.source,
                        "destination": rule.destination[:3] if rule.destination and len(rule.destination) > 3 else rule.destination,
                        "application": rule.application[:3] if rule.application and len(rule.application) > 3 else rule.application,
                        "service": rule.service,
                        "disabled": rule.disabled,
                        "description": rule.description or ""
                    }
                    break
                    
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def verify_object_existence(self, object_type: str, object_name: str, 
                               device_group_name: str = None, 
                               check_shared_first: bool = True) -> Dict[str, Any]:
        """
        Verify if an object exists in Shared context or a specific device group
        
        Args:
            object_type: Type of object (address_object, address_group, service_object, service_group, pre_rule, post_rule)
            object_name: Name of the object to verify
            device_group_name: Optional device group name (if None, only check shared)
            check_shared_first: If True, check shared first, then device group; if False, reverse order
            
        Returns:
            Comprehensive verification results
        """
        results = {
            "timestamp": datetime.now().isoformat(),
            "panorama": self.hostname,
            "object_type": object_type,
            "object_name": object_name,
            "target_device_group": device_group_name,
            "found": False,
            "found_in_shared": False,
            "found_in_device_group": False,
            "locations": [],
            "shared_check": None,
            "device_group_check": None,
            "all_checks": []
        }
        
        # Determine check order
        checks = []
        if check_shared_first:
            checks.append(("shared", None))
            if device_group_name:
                checks.append(("device_group", device_group_name))
        else:
            if device_group_name:
                checks.append(("device_group", device_group_name))
            checks.append(("shared", None))
        
        # Perform checks
        for check_type, dg_name in checks:
            if check_type == "shared":
                result = self._check_in_shared(object_type, object_name)
                results["shared_check"] = result
                if result["exists"]:
                    results["found"] = True
                    results["found_in_shared"] = True
                    results["locations"].append("shared")
            else:
                result = self._check_in_device_group(object_type, object_name, dg_name)
                results["device_group_check"] = result
                if result["exists"]:
                    results["found"] = True
                    results["found_in_device_group"] = True
                    results["locations"].append(f"device_group:{dg_name}")
        
        results["all_checks"] = [results["shared_check"], results["device_group_check"]] if device_group_name else [results["shared_check"]]
        
        return results
    
    def _check_in_shared(self, object_type: str, object_name: str) -> Dict[str, Any]:
        """Check if object exists in shared context"""
        verifiers = {
            "address_object": self.check_address_object,
            "address_group": self.check_address_group,
            "service_object": self.check_service_object,
            "service_group": self.check_service_group
        }
        
        verifier = verifiers.get(object_type.lower())
        if verifier:
            return verifier(object_name, None)
        else:
            return {
                "object_type": object_type,
                "object_name": object_name,
                "exists": False,
                "location": None,
                "error": f"Cannot check {object_type} in shared context (only supported in device groups)"
            }
    
    def _check_in_device_group(self, object_type: str, object_name: str, device_group_name: str) -> Dict[str, Any]:
        """Check if object exists in a device group"""
        # Find the device group
        device_group = None
        for dg in self.get_all_device_groups():
            if dg.name == device_group_name:
                device_group = dg
                break
        
        if not device_group:
            return {
                "object_type": object_type,
                "object_name": object_name,
                "exists": False,
                "location": None,
                "error": f"Device group '{device_group_name}' not found"
            }
        
        verifiers = {
            "address_object": self.check_address_object,
            "address_group": self.check_address_group,
            "service_object": self.check_service_object,
            "service_group": self.check_service_group,
            "pre_rule": lambda name, dg: self.check_security_rule(name, dg, "pre"),
            "post_rule": lambda name, dg: self.check_security_rule(name, dg, "post")
        }
        
        verifier = verifiers.get(object_type.lower())
        if verifier:
            return verifier(object_name, device_group)
        else:
            return {
                "object_type": object_type,
                "object_name": object_name,
                "exists": False,
                "location": None,
                "error": f"Unsupported object type: {object_type}"
            }
    
    def verify_multiple_objects(self, objects_to_check: List[Dict[str, str]], 
                               default_device_group: str = None,
                               check_shared_first: bool = True) -> List[Dict[str, Any]]:
        """
        Verify multiple objects
        
        Args:
            objects_to_check: List of objects with type, name, and optional device_group
            default_device_group: Default device group if not specified per object
            check_shared_first: Order of checking
            
        Returns:
            List of verification results
        """
        results = []
        
        for obj in objects_to_check:
            obj_type = obj.get("type")
            obj_name = obj.get("name")
            device_group = obj.get("device_group", default_device_group)
            
            if not obj_type or not obj_name:
                continue
            
            result = self.verify_object_existence(obj_type, obj_name, device_group, check_shared_first)
            results.append(result)
        
        return results
    
    def print_verification_result(self, result: Dict[str, Any], verbose: bool = False):
        """
        Print formatted verification result
        
        Args:
            result: Verification result dictionary
            verbose: If True, print detailed object information
        """
        print(f"\n{Fore.CYAN}{'='*70}{Fore.RESET}")
        print(f"{Fore.YELLOW}Object: {result['object_name']} ({result['object_type']}){Fore.RESET}")
        print(f"{Fore.CYAN}{'='*70}{Fore.RESET}")
        
        if result['found']:
            print(f"{Fore.GREEN}✓ STATUS: FOUND{Fore.RESET}")
            print(f"{Fore.GREEN}  Locations: {', '.join(result['locations'])}{Fore.RESET}")
        else:
            print(f"{Fore.RED}✗ STATUS: NOT FOUND{Fore.RESET}")
            if result['target_device_group']:
                print(f"{Fore.YELLOW}  Checked in: shared and device group '{result['target_device_group']}'{Fore.RESET}")
            else:
                print(f"{Fore.YELLOW}  Checked in: shared context only{Fore.RESET}")
        
        # Print details from where it was found
        if result['found_in_shared'] and result['shared_check'] and result['shared_check'].get('details'):
            print(f"\n{Fore.CYAN}Shared Context Details:{Fore.RESET}")
            self._print_object_details(result['shared_check']['details'])
        
        if result['found_in_device_group'] and result['device_group_check'] and result['device_group_check'].get('details'):
            print(f"\n{Fore.CYAN}Device Group Details:{Fore.RESET}")
            self._print_object_details(result['device_group_check']['details'])
        
        # Verbose output for all checks
        if verbose:
            print(f"\n{Fore.CYAN}Detailed Check Information:{Fore.RESET}")
            for check in result['all_checks']:
                if check:
                    location = check.get('location', 'unknown')
                    exists = check.get('exists', False)
                    status = f"{Fore.GREEN}✓ Found{Fore.RESET}" if exists else f"{Fore.RED}✗ Not Found{Fore.RESET}"
                    print(f"  {status} in {location}")
                    if check.get('error'):
                        print(f"    {Fore.RED}Error: {check['error']}{Fore.RESET}")
    
    def _print_object_details(self, details: Dict[str, Any]):
        """Print object details in a formatted way"""
        for key, value in details.items():
            if value:
                if key == "members" and isinstance(value, list):
                    print(f"  {key}: {len(value)} member(s)")
                    if len(value) <= 5:
                        for member in value:
                            print(f"    - {member}")
                    else:
                        for member in value[:5]:
                            print(f"    - {member}")
                        print(f"    ... and {len(value) - 5} more")
                elif key == "member_count":
                    print(f"  Total Members: {value}")
                elif key not in ["member_count"]:
                    print(f"  {key}: {value}")
    
    def print_summary_table(self, results: List[Dict[str, Any]]):
        """
        Print a summary table for multiple verification results
        
        Args:
            results: List of verification results
        """
        print(f"\n{Fore.CYAN}{'='*80}{Fore.RESET}")
        print(f"{Fore.YELLOW}VERIFICATION SUMMARY TABLE{Fore.RESET}")
        print(f"{Fore.CYAN}{'='*80}{Fore.RESET}")
        
        # Header
        print(f"{'Object Name':<30} {'Type':<20} {'Status':<10} {'Location':<20}")
        print(f"{'-'*80}")
        
        # Rows
        for result in results:
            name = result['object_name'][:27] + "..." if len(result['object_name']) > 30 else result['object_name']
            obj_type = result['object_type'][:17] + "..." if len(result['object_type']) > 20 else result['object_type']
            
            if result['found']:
                status = f"{Fore.GREEN}FOUND{Fore.RESET}"
                location = ', '.join(result['locations'])[:17]
            else:
                status = f"{Fore.RED}NOT FOUND{Fore.RESET}"
                location = "N/A"
            
            print(f"{name:<30} {obj_type:<20} {status:<10} {location:<20}")
        
        print(f"{Fore.CYAN}{'='*80}{Fore.RESET}")
        
        # Summary statistics
        total = len(results)
        found = sum(1 for r in results if r['found'])
        found_in_shared = sum(1 for r in results if r['found_in_shared'])
        found_in_dg = sum(1 for r in results if r['found_in_device_group'])
        
        print(f"\n{Fore.CYAN}Statistics:{Fore.RESET}")
        print(f"  Total Objects Checked: {total}")
        print(f"  {Fore.GREEN}Found: {found}{Fore.RESET}")
        print(f"  {Fore.RED}Not Found: {total - found}{Fore.RESET}")
        print(f"  {Fore.CYAN}Found in Shared: {found_in_shared}{Fore.RESET}")
        print(f"  {Fore.CYAN}Found in Device Groups: {found_in_dg}{Fore.RESET}")
    
    def save_results(self, results: Any, output_file: str):
        """Save results to JSON file"""
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\n{Fore.GREEN}[+] Results saved to: {output_file}{Fore.RESET}")
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to save results: {e}{Fore.RESET}")


def create_verification_file_template(output_file: str):
    """Create a template JSON file for batch verification"""
    template = {
        "description": "Template for verifying Panorama objects in Shared and Device Group contexts",
        "default_device_group": "Production",  # Optional default device group
        "check_shared_first": True,  # If True, check shared before device group
        "objects": [
            {
                "type": "address_object",
                "name": "web-server-01",
                "comment": "Will check shared first, then default device group"
            },
            {
                "type": "address_group",
                "name": "web-servers-group",
                "device_group": "DMZ",  # Override device group for this object
                "comment": "Check in specific device group only"
            },
            {
                "type": "service_object",
                "name": "custom-https",
                "comment": "Check in shared only (no device group specified)"
            },
            {
                "type": "address_object",
                "name": "dns-servers",
                "check_shared_only": True,  # Only check shared, skip device group
                "comment": "Only check in shared context"
            },
            {
                "type": "pre_rule",
                "name": "allow-web-traffic",
                "device_group": "Production",
                "comment": "Check security rule in pre-rulebase"
            },
            {
                "type": "post_rule",
                "name": "block-malicious",
                "device_group": "Production",
                "comment": "Check security rule in post-rulebase"
            }
        ]
    }
    
    try:
        with open(output_file, 'w') as f:
            json.dump(template, f, indent=2)
        print(Fore.GREEN + f"[+] Template created: {output_file}" + Fore.RESET)
        print(Fore.YELLOW + "[!] Edit the file with your object names and device groups" + Fore.RESET)
    except Exception as e:
        print(Fore.RED + f"[-] Failed to create template: {e}" + Fore.RESET)


def main():
    parser = argparse.ArgumentParser(
        description="Verify if objects exist in Shared context or Device Groups on Panorama",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check single object in shared context only
  %(prog)s --host panorama.example.com --api-key KEY \\
      --object-type address_object --object-name "Shared-Web-Server"
  
  # Check object in shared first, then specific device group
  %(prog)s --host panorama.example.com --username admin --password pass \\
      --object-type address_group --object-name "Global-Servers" \\
      --device-group "Production" --check-shared-first
  
  # Check object in device group only (skip shared)
  %(prog)s --host panorama.example.com --api-key KEY \\
      --object-type service_object --object-name "Custom-SSH" \\
      --device-group "DMZ" --skip-shared
  
  # Batch verify from JSON file
  %(prog)s --host panorama.example.com --api-key KEY \\
      --verify-file objects.json --output results.json --verbose
  
  # Create template file
  %(prog)s --create-template verification_template.json

Supported Object Types:
  - address_object  : IPv4/IPv6 address, range, or FQDN
  - address_group   : Static or dynamic address group
  - service_object  : TCP/UDP service definition
  - service_group   : Group of service objects
  - pre_rule        : Security rule in pre-rulebase (device group only)
  - post_rule       : Security rule in post-rulebase (device group only)
        """
    )
    
    # Authentication
    parser.add_argument("--host", help="Panorama hostname or IP")
    parser.add_argument("--username", help="Username")
    parser.add_argument("--password", help="Password")
    parser.add_argument("--api-key", help="API key")
    
    # Verification options
    parser.add_argument("--object-type", help="Type of object to verify")
    parser.add_argument("--object-name", help="Name of the object to verify")
    parser.add_argument("--device-group", help="Device group to check (optional)")
    parser.add_argument("--check-shared-first", action="store_true", 
                       help="Check shared context before device group (default: True)")
    parser.add_argument("--skip-shared", action="store_true",
                       help="Skip checking shared context (only check device group)")
    
    # Batch verification
    parser.add_argument("--verify-file", help="JSON file with objects to verify")
    parser.add_argument("--output", "-o", help="Output file for results")
    parser.add_argument("--create-template", metavar="FILE", help="Create template file")
    
    # Output options
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--summary-only", action="store_true", help="Show only summary table")
    
    args = parser.parse_args()
    
    # Handle template creation
    if args.create_template:
        create_verification_file_template(args.create_template)
        sys.exit(0)
    
    # Validate verification arguments
    if not args.host:
        parser.error("--host is required for verification")
    
    if not args.api_key and not (args.username and args.password):
        parser.error("Either --api-key or both --username and --password are required")
    
    # Initialize verifier
    try:
        verifier = PanoramaObjectExistenceVerifier(
            hostname=args.host,
            username=args.username,
            password=args.password,
            api_key=args.api_key
        )
        
        # Batch verification from file
        if args.verify_file:
            with open(args.verify_file, 'r') as f:
                data = json.load(f)
            
            # Handle different file formats
            if isinstance(data, list):
                objects_to_check = data
                default_device_group = args.device_group
                check_shared_first = not args.skip_shared
            else:
                objects_to_check = data.get("objects", [])
                default_device_group = data.get("default_device_group", args.device_group)
                check_shared_first = data.get("check_shared_first", not args.skip_shared)
            
            # Run verification
            results = verifier.verify_multiple_objects(
                objects_to_check, 
                default_device_group, 
                check_shared_first
            )
            
            # Display results
            if args.summary_only:
                verifier.print_summary_table(results)
            else:
                for result in results:
                    verifier.print_verification_result(result, args.verbose)
                if len(results) > 1:
                    verifier.print_summary_table(results)
            
            # Save results
            if args.output:
                verifier.save_results(results, args.output)
        
        # Single object verification
        elif args.object_type and args.object_name:
            # Determine check order
            if args.skip_shared:
                check_shared_first = False
            else:
                check_shared_first = args.check_shared_first or not args.device_group
            
            result = verifier.verify_object_existence(
                args.object_type,
                args.object_name,
                args.device_group,
                check_shared_first
            )
            
            verifier.print_verification_result(result, args.verbose)
            
            if args.output:
                verifier.save_results(result, args.output)
            
            # Exit with appropriate code (0 if found, 1 if not found)
            sys.exit(0 if result['found'] else 1)
        
        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Operation cancelled{Fore.RESET}")
        sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Fore.RESET)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
