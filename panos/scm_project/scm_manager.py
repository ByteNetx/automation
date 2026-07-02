#!/usr/bin/env python3
"""
Strata Cloud Manager Automation Script - JSON, Class-based Implementation

This script reads configuration from JSON files and creates address objects,
address groups, URL categories, and security rules with folder/snippet scope in SCM.
"""

import os
import json
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from scm.client import Scm
from scm.config.objects import Address, AddressGroup
from scm.config.security import URLCategories, SecurityRule
from scm.models.security.url_categories import URLCategoriesListTypeEnum


# ============================================================
# ENUMS AND DATA CLASSES
# ============================================================

class ScopeType(Enum):
    """Configuration scope types in SCM"""
    FOLDER = "folder"
    SNIPPET = "snippet"
    DEVICE = "device"


class ActionType(Enum):
    """Security rule action types"""
    ALLOW = "allow"
    DENY = "deny"
    DROP = "drop"
    RESET = "reset"


class SearchFilter(Enum):
    """Search filter types"""
    NAME = "name"
    TAG = "tag"
    DESCRIPTION = "description"
    TYPE = "type"  # For address types: ip_netmask, fqdn, ip_range
    ACTION = "action"  # For security rules


@dataclass
class AddressObject:
    """Data class for Address Object configuration"""
    name: str
    description: str = ""
    ip_netmask: Optional[str] = None
    fqdn: Optional[str] = None
    ip_range: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    id: Optional[str] = None  # For tracking existing objects
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AddressObject':
        """Create AddressObject from dictionary"""
        return cls(
            name=data.get('name', ''),
            description=data.get('description', ''),
            ip_netmask=data.get('ip_netmask'),
            fqdn=data.get('fqdn'),
            ip_range=data.get('ip_range'),
            tags=data.get('tags', []),
            id=data.get('id')
        )
    
    @classmethod
    def from_api_response(cls, response) -> 'AddressObject':
        """Create AddressObject from API response"""
        return cls(
            name=response.name,
            description=getattr(response, 'description', ''),
            ip_netmask=getattr(response, 'ip_netmask', None),
            fqdn=getattr(response, 'fqdn', None),
            ip_range=getattr(response, 'ip_range', None),
            tags=getattr(response, 'tag', []),
            id=getattr(response, 'id', None)
        )
    
    def to_dict(self, scope_type: ScopeType, scope_value: str) -> Dict[str, Any]:
        """Convert to SCM API format"""
        data = {
            "name": self.name,
            "description": self.description,
            scope_type.value: scope_value,
        }
        
        if self.tags:
            data["tag"] = self.tags
            
        if self.ip_netmask:
            data["ip_netmask"] = self.ip_netmask
        elif self.fqdn:
            data["fqdn"] = self.fqdn
        elif self.ip_range:
            data["ip_range"] = self.ip_range
        else:
            raise ValueError(f"Address {self.name} must have one of: ip_netmask, fqdn, or ip_range")
            
        return data
    
    def get_type(self) -> str:
        """Get the type of address object"""
        if self.ip_netmask:
            return "ip_netmask"
        elif self.fqdn:
            return "fqdn"
        elif self.ip_range:
            return "ip_range"
        return "unknown"


@dataclass
class AddressGroupObject:
    """Data class for Address Group configuration"""
    name: str
    description: str = ""
    static_members: List[str] = field(default_factory=list)
    dynamic_filter: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    id: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AddressGroupObject':
        """Create AddressGroupObject from dictionary"""
        return cls(
            name=data.get('name', ''),
            description=data.get('description', ''),
            static_members=data.get('static_members', []),
            dynamic_filter=data.get('dynamic_filter'),
            tags=data.get('tags', []),
            id=data.get('id')
        )
    
    @classmethod
    def from_api_response(cls, response) -> 'AddressGroupObject':
        """Create AddressGroupObject from API response"""
        return cls(
            name=response.name,
            description=getattr(response, 'description', ''),
            static_members=getattr(response, 'static', []),
            dynamic_filter=getattr(response, 'dynamic', {}).get('filter') if hasattr(response, 'dynamic') else None,
            tags=getattr(response, 'tag', []),
            id=getattr(response, 'id', None)
        )
    
    def to_dict(self, scope_type: ScopeType, scope_value: str) -> Dict[str, Any]:
        """Convert to SCM API format"""
        data = {
            "name": self.name,
            "description": self.description,
            scope_type.value: scope_value,
        }
        
        if self.tags:
            data["tag"] = self.tags
            
        if self.static_members:
            data["static"] = self.static_members
        elif self.dynamic_filter:
            data["dynamic"] = {"filter": self.dynamic_filter}
        else:
            raise ValueError(f"Group {self.name} must have either static_members or dynamic_filter")
            
        return data


@dataclass
class URLCategoryObject:
    """Data class for URL Category configuration"""
    name: str
    description: str = ""
    url_list: List[str] = field(default_factory=list)
    id: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'URLCategoryObject':
        """Create URLCategoryObject from dictionary"""
        return cls(
            name=data.get('name', ''),
            description=data.get('description', ''),
            url_list=data.get('url_list', []),
            id=data.get('id')
        )
    
    @classmethod
    def from_api_response(cls, response) -> 'URLCategoryObject':
        """Create URLCategoryObject from API response"""
        return cls(
            name=response.name,
            description=getattr(response, 'description', ''),
            url_list=getattr(response, 'list', []),
            id=getattr(response, 'id', None)
        )
    
    def to_dict(self, scope_type: ScopeType, scope_value: str) -> Dict[str, Any]:
        """Convert to SCM API format"""
        return {
            "name": self.name,
            "description": self.description,
            scope_type.value: scope_value,
            "type": URLCategoriesListTypeEnum.url_list,
            "list": self.url_list,
        }


@dataclass
class SecurityRuleObject:
    """Data class for Security Rule configuration"""
    name: str
    description: str = ""
    source_zones: List[str] = field(default_factory=list)
    destination_zones: List[str] = field(default_factory=list)
    source_addresses: List[str] = field(default_factory=list)
    destination_addresses: List[str] = field(default_factory=list)
    applications: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    url_categories: List[str] = field(default_factory=list)
    action: ActionType = ActionType.ALLOW
    log_start: bool = False
    log_end: bool = True
    tags: List[str] = field(default_factory=list)
    position: Optional[str] = None
    id: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityRuleObject':
        """Create SecurityRuleObject from dictionary"""
        action = data.get('action', 'allow')
        if isinstance(action, str):
            action = ActionType(action.lower())
        
        return cls(
            name=data.get('name', ''),
            description=data.get('description', ''),
            source_zones=data.get('source_zones', []),
            destination_zones=data.get('destination_zones', []),
            source_addresses=data.get('source_addresses', []),
            destination_addresses=data.get('destination_addresses', []),
            applications=data.get('applications', []),
            services=data.get('services', []),
            url_categories=data.get('url_categories', []),
            action=action,
            log_start=data.get('log_start', False),
            log_end=data.get('log_end', True),
            tags=data.get('tags', []),
            position=data.get('position'),
            id=data.get('id')
        )
    
    @classmethod
    def from_api_response(cls, response) -> 'SecurityRuleObject':
        """Create SecurityRuleObject from API response"""
        action = getattr(response, 'action', 'allow')
        if isinstance(action, str):
            action = ActionType(action.lower())
        
        return cls(
            name=response.name,
            description=getattr(response, 'description', ''),
            source_zones=getattr(response, 'source_zones', []),
            destination_zones=getattr(response, 'destination_zones', []),
            source_addresses=getattr(response, 'source_addresses', []),
            destination_addresses=getattr(response, 'destination_addresses', []),
            applications=getattr(response, 'applications', []),
            services=getattr(response, 'services', []),
            url_categories=getattr(response, 'url_categories', []),
            action=action,
            log_start=getattr(response, 'log_start', False),
            log_end=getattr(response, 'log_end', True),
            tags=getattr(response, 'tag', []),
            position=getattr(response, 'position', None),
            id=getattr(response, 'id', None)
        )
    
    def to_dict(self, scope_type: ScopeType, scope_value: str) -> Dict[str, Any]:
        """Convert to SCM API format"""
        data = {
            "name": self.name,
            "description": self.description,
            scope_type.value: scope_value,
            "source_zones": self.source_zones or ["any"],
            "destination_zones": self.destination_zones or ["any"],
            "source_addresses": self.source_addresses or ["any"],
            "destination_addresses": self.destination_addresses or ["any"],
            "applications": self.applications or ["any"],
            "services": self.services or ["any"],
            "action": self.action.value,
            "log_start": self.log_start,
            "log_end": self.log_end,
        }
        
        if self.url_categories:
            data["url_categories"] = self.url_categories
            
        if self.tags:
            data["tag"] = self.tags
            
        if self.position:
            data["position"] = self.position
            
        return data


# ============================================================
# CONFIGURATION DATA LOADER
# ============================================================

class ConfigLoader:
    """Load and parse configuration from JSON files"""
    
    @staticmethod
    def load_objects(file_path: str) -> List[AddressObject]:
        """Load objects from JSON file"""
        with open(file_path, 'r') as f:
            data = json.load(f)
        objects_data = {}
        if "addresses" in data:
            objects_data.update({"addresses": [AddressObject.from_dict(item) for item in data.get('addresses', [])]})
        if "address_groups" in data:
            objects_data.update({"address_grous": [AddressGroupObject.from_dict(item) for item in data.get('address_groups', [])]})
        if "url_categories" in data:
            objects_data.update({"url_categories": [URLCategoryObject.from_dict(item) for item in data.get('url_categories', [])]})
        return objects_data

    @staticmethod
    def load_security_rules(file_path: str) -> List[SecurityRuleObject]:
        """Load security rules from JSON file"""
        with open(file_path, 'r') as f:
            data = json.load(f)
        return [SecurityRuleObject.from_dict(item) for item in data.get('security_rules', [])]
    
    @staticmethod
    def load_scope(file_path: str) -> Dict[str, Any]:
        """Load scope from JSON file"""
        with open(file_path, 'r') as f:
            data = json.load(f)
        return data.get('scope', {})



# ============================================================
# MAIN MANAGER CLASS
# ============================================================

class SCMConfigManager:
    """
    Manager class for SCM objects and security rules with proper scoping
    """
    
    def __init__(self, client_id: str, client_secret: str, tsg_id: str):
        """
        Initialize SCM client and service objects
        
        Args:
            client_id: SCM API client ID
            client_secret: SCM API client secret
            tsg_id: Tenant Service Group ID
        """
        self.client = Scm(
            client_id=client_id,
            client_secret=client_secret,
            tsg_id=tsg_id,
        )
        
        # Initialize service objects
        self.address_service = Address(self.client)
        self.address_group_service = AddressGroup(self.client)
        self.url_category_service = URLCategories(self.client)
        self.security_rule_service = SecurityRule(self.client)
        
        # Track created objects
        self.created_objects = {
            "addresses": [],
            "address_groups": [],
            "url_categories": [],
            "security_rules": []
        }
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def create_scm_objects(
        self,
        scope: Dict,
        config_data: Dict[str: List[str]]
    ) -> List[str]:
        """
        Create multiple address, address group, url categpry, 
        and security rule objects in a scope.
        
        Args:
            scope: Dict of configuration scope
            config_data: Dict of list objects
            
        Returns:
            List of created object names
        """
        scope_type = scope.get("scope_type", "folder")
        scope_value = scope.get("scope_value", "All")
        created = []
        if "addresses" in config_data:
            for addr in config_data["addresses"]:
                try:
                    data = addr.to_dict(scope_type, scope_value)
                    response = self.address_service.create(data)
                    created.append(f"address_object-{response.name}")
                    self.created_objects["addresses"].append(response.name)
                    self.logger.info(f"✅ Created address: {response.name} (ID: {response.id})")
                except Exception as e:
                    self.logger.error(f"❌ Failed to create address {addr.name}: {e}")

        if "address_groups" in config_data:
            for group in config_data["address_groups"]:
                try:
                    data = group.to_dict(scope_type, scope_value)
                    response = self.address_group_service.create(data)
                    created.append(f"address_group-{response.name}")
                    self.created_objects["address_groups"].append(response.name)
                    self.logger.info(f"✅ Created address group: {response.name} (ID: {response.id})")
                except Exception as e:
                    self.logger.error(f"❌ Failed to create address group {group.name}: {e}")

        if "url_categories" in config_data:
            for category in config_data["url_categories"]:
                try:
                    data = category.to_dict(scope_type, scope_value)
                    response = self.url_category_service.create(data)
                    created.append(f"url_category-{response.name}")
                    self.created_objects["url_categories"].append(response.name)
                    self.logger.info(f"✅ Created URL category: {response.name} (ID: {response.id})")
                except Exception as e:
                    self.logger.error(f"❌ Failed to create URL category {category.name}: {e}")

        if "security_rules" in config_data:
            for rule in config_data["security_rules"]:
                try:
                    data = rule.to_dict(scope_type, scope_value)
                    response = self.security_rule_service.create(data)
                    created.append(f"security_rule-{response.name}")
                    self.created_objects["security_rules"].append(response.name)
                    self.logger.info(f"✅ Created security rule: {response.name} (ID: {response.id})")
                except Exception as e:
                    self.logger.error(f"❌ Failed to create security rule {rule.name}: {e}")

        return created


    def get_security_rules_by_scope(
        self,
        scope: Dict,
        name: str,
        rule_type: Optional[str] = None,  # "pre", "post", or "default"
        limit: Optional[int] = None
    ) -> List[SecurityRuleObject]:
        """
        Get security rules by scope (folder, snippet, or device)
        
        Args:
            scope: Dict of scope to retrieve
            name: Specific rule name to retrieve
            rule_type: Type of rule ("pre", "post", or "default")
            limit: Maximum number of results to return
            
        Returns:
            List of SecurityRuleObject instances
        """
        try:
            scope_type = scope.get("scope_type")
            scope_value = scope.get("scope_value")
            # Build filter parameters
            filter_params = {}
    
            filter_params[scope_type] = scope_type
            filter_params[scope_value] = scope_value

            if name:
                filter_params["name"] = name
            
            if rule_type:
                filter_params["type"] = rule_type
            
            # Get rules with filters
            self.logger.info("="*60)
            self.logger.info(f"🔍 Search security rules by scope '{scope_type}-{scope_value}' on SCM")
            self.logger.info("="*60)
            response = self.manager.security_rule_service.list(**filter_params)
            rules = [SecurityRuleObject.from_api_response(rule) for rule in response]
            
            return rules
            
        except Exception as e:
            self.logger.error(f"Error getting security rules by scope: {e}")
            return []
    
    def get_scm_object_by_name(self, scope, objects_data: Dict) -> Dict[str, List]:
        search_results = {
            "address_objects": [],
            "address_groups": [],
            "url_categories": [],
            "security_rules": []
        }
        try:
            self.logger.info("="*60)
            self.logger.info("🔍 Search objects or security rules by their names on SCM")
            self.logger.info("="*60)
            if objects_data["addresses"]:
                for addr in objects_data["addresses"]:
                    response = self.manager.address_service.get(addr.get("name"))
                    search_results["address_objects"].append(AddressObject.from_api_response(response))
            if objects_data["address_groups"]:
                for addr_group in objects_data["address_groups"]:
                    response = self.manager.address_group_service.get(addr_group.get("name"))
                    search_results["address_groups"].append(AddressGroupObject.from_api_response(response))
            if objects_data["url_categories"]:
                for url in objects_data["url_categories"]:
                    response = self.manager.url_category_service.get(url.get("name"))
                    search_results["url_categories"].append(URLCategoryObject.from_api_response(response))
            if objects_data["security_rule"]:
                for rule in objects_data["security_rule"]:
                    response = self.manager.security_rule_service.get(rule.get("name"))
                    search_results["security_rules"].append(SecurityRuleObject.from_api_response(response))
            return search_results
        except Exception as e:
            self.logger.error(f"Error getting object by name: {e}")
            return None

    
    def print_search_results(self, results: Dict, title: str, show_scope: bool = True) -> None:
        """Pretty print search results"""
        if not results:
            self.logger.info(f"📭 No {title} found matching criteria")
            return
        
        self.logger.info(f"\n🔍 SEARCH RESULTS: {title} (Found: {len(results)})")
        self.logger.info("=" * 80)
        for idx, obj in enumerate(results, 1):
            if isinstance(obj, AddressObject):
                self.logger.info(f"{idx}. {obj.name} [{obj.get_type()}] - {obj.description[:50]}")
                if show_scope and obj.get_scope():
                    self.logger.info(f"   Scope: {obj.get_scope()}")
                if obj.tags:
                    self.logger.info(f"   Tags: {', '.join(obj.tags)}")
                self.logger.info(f"   ID: {obj.id}")
            
            elif isinstance(obj, AddressGroupObject):
                group_type = "Dynamic" if obj.dynamic_filter else "Static"
                member_count = len(obj.static_members)
                self.logger.info(f"{idx}. {obj.name} [{group_type}, {member_count} members] - {obj.description[:50]}")
                if show_scope and obj.get_scope():
                    self.logger.info(f"   Scope: {obj.get_scope()}")
                if obj.dynamic_filter:
                    self.logger.info(f"   Filter: {obj.dynamic_filter}")
                if obj.tags:
                    self.logger.info(f"   Tags: {', '.join(obj.tags)}")
                self.logger.info(f"   ID: {obj.id}")
            
            elif isinstance(obj, URLCategoryObject):
                self.logger.info(f"{idx}. {obj.name} [{len(obj.url_list)} URLs] - {obj.description[:50]}")
                if show_scope and obj.get_scope():
                    self.logger.info(f"   Scope: {obj.get_scope()}")
                if obj.url_list:
                    self.logger.info(f"   URLs: {', '.join(obj.url_list[:3])}{'...' if len(obj.url_list) > 3 else ''}")
                self.logger.info(f"   ID: {obj.id}")
            
            elif isinstance(obj, SecurityRuleObject):
                self.logger.info(f"{idx}. {obj.name} [{obj.action.value.upper()}] - {obj.description[:50]}")
                if show_scope and obj.get_scope():
                    self.logger.info(f"   Scope: {obj.get_scope()}")
                self.logger.info(f"   Source: {', '.join(obj.source_zones)} -> Dest: {', '.join(obj.destination_zones)}")
                self.logger.info(f"   Apps: {', '.join(obj.applications[:5])}{'...' if len(obj.applications) > 5 else ''}")
                if obj.url_categories:
                    self.logger.info(f"   URL Categories: {', '.join(obj.url_categories)}")
                if obj.tags:
                    self.logger.info(f"   Tags: {', '.join(obj.tags)}")
                self.logger.info(f"   ID: {obj.id}")
            self.logger.info("-" * 40)


# ============================================================
# MAIN EXECUTION
# ============================================================

def main():
    """
    Main function demonstrating JSON-driven approach
    """
    
    # Arguments
    CLIENT_ID = os.environ.get("SCM_CLIENT_ID", "your_client_id")
    CLIENT_SECRET = os.environ.get("SCM_CLIENT_SECRET", "your_client_secret")
    TSG_ID = os.environ.get("SCM_TSG_ID", "your_tsg_id")
    CONFIG_DIR = os.environ.get("SCM_CONFIG_DIR", "config")
    SCOPE = {}
    OPERATION = "list"

    # Get configuration data
    scope_data = ConfigLoader.load_scope(
        os.path.join(CONFIG_DIR, "scope.json")
    )
    SCOPE["scope_type"] = ScopeType(scope_data.get('type', 'folder'))
    SCOPE["scope_value"] = scope_data.get('value', 'All')

    objects_data = ConfigLoader.load_objects(
        os.path.join(CONFIG_DIR, "objects.json")
    )

    rules_data = ConfigLoader.load_security_rules(
        os.path.join(CONFIG_DIR, "rules.json")
    )
    
    # Initialize manager
    manager = SCMConfigManager(CLIENT_ID, CLIENT_SECRET, TSG_ID)
    
    # Create all objects from JSON files
    if OPERATION == "create":
        if objects_data:
            results = manager.create_scm_objects(SCOPE, objects_data)
        if rules_data:
            results = manager.create_scm_objects(SCOPE, rules_data)
    
    elif OPERATION == "list":
        if objects_data:
            results = manager.get_scm_object_by_name(objects_data)
        if rules_data:
            results = manager.get_security_rules_by_scope(SCOPE, rules_data)

    # Print detailed results
    if any(results.values()):
        manager.print_search_results(results)


if __name__ == "__main__":
    main()
