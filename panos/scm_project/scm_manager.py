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


@dataclass
class AddressObject:
    """Data class for Address Object configuration"""
    name: str
    description: str = ""
    ip_netmask: Optional[str] = None
    fqdn: Optional[str] = None
    ip_range: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AddressObject':
        """Create AddressObject from dictionary"""
        return cls(
            name=data.get('name', ''),
            description=data.get('description', ''),
            ip_netmask=data.get('ip_netmask'),
            fqdn=data.get('fqdn'),
            ip_range=data.get('ip_range'),
            tags=data.get('tags', [])
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


@dataclass
class AddressGroupObject:
    """Data class for Address Group configuration"""
    name: str
    description: str = ""
    static_members: List[str] = field(default_factory=list)
    dynamic_filter: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AddressGroupObject':
        """Create AddressGroupObject from dictionary"""
        return cls(
            name=data.get('name', ''),
            description=data.get('description', ''),
            static_members=data.get('static_members', []),
            dynamic_filter=data.get('dynamic_filter'),
            tags=data.get('tags', [])
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
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'URLCategoryObject':
        """Create URLCategoryObject from dictionary"""
        return cls(
            name=data.get('name', ''),
            description=data.get('description', ''),
            url_list=data.get('url_list', [])
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
            position=data.get('position')
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
# CONFIGURATION LOADER
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
    def load_scope_config(file_path: str) -> Dict[str, Any]:
        """Load scope configuration from JSON file"""
        with open(file_path, 'r') as f:
            data = json.load(f)
        return data.get('scope', {})


# ============================================================
# MAIN MANAGER CLASS
# ============================================================

class SCMObjectManager:
    """
    Manager class for creating SCM objects with proper scoping
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
    
    def create_objects(
        self, 
        objects_data: Dict[str: List[str]], 
        scope_type: ScopeType,
        scope_value: str
    ) -> List[str]:
        """
        Create multiple objects
        
        Args:
            objects_data: Dict of list objects
            scope_type: Scope type (folder, snippet, or device)
            scope_value: Scope container name
            
        Returns:
            List of created object names
        """
        created = []
        if "addresses" in objects_data:
            for addr in objects_data["addresses"]:
                try:
                    data = addr.to_dict(scope_type, scope_value)
                    response = self.address_service.create(data)
                    created.append(response.name)
                    self.created_objects["addresses"].append(response.name)
                    self.logger.info(f"✅ Created address: {response.name} (ID: {response.id})")
                except Exception as e:
                    self.logger.error(f"❌ Failed to create address {addr.name}: {e}")

        if "address_groups" in objects_data:
            for group in objects_data["address_groups"]:
                try:
                    data = group.to_dict(scope_type, scope_value)
                    response = self.address_group_service.create(data)
                    created.append(response.name)
                    self.created_objects["address_groups"].append(response.name)
                    self.logger.info(f"✅ Created address group: {response.name} (ID: {response.id})")
                except Exception as e:
                    self.logger.error(f"❌ Failed to create address group {group.name}: {e}")

        if "url_categories" in objects_data:
            for category in objects_data["url_categories"]:
                try:
                    data = category.to_dict(scope_type, scope_value)
                    response = self.url_category_service.create(data)
                    created.append(response.name)
                    self.created_objects["url_categories"].append(response.name)
                    self.logger.info(f"✅ Created URL category: {response.name} (ID: {response.id})")
                except Exception as e:
                    self.logger.error(f"❌ Failed to create URL category {category.name}: {e}")
        return created
    
    def create_security_rules(
        self,
        rules: List[SecurityRuleObject],
        scope_type: ScopeType,
        scope_value: str
    ) -> List[str]:
        """
        Create multiple security rules
        
        Args:
            rules: List of SecurityRuleObject instances
            scope_type: Scope type (folder, snippet, or device)
            scope_value: Scope container name
            
        Returns:
            List of created rule names
        """
        created = []
        for rule in rules:
            try:
                data = rule.to_dict(scope_type, scope_value)
                response = self.security_rule_service.create(data)
                created.append(response.name)
                self.created_objects["security_rules"].append(response.name)
                self.logger.info(f"✅ Created security rule: {response.name} (ID: {response.id})")
            except Exception as e:
                self.logger.error(f"❌ Failed to create security rule {rule.name}: {e}")
        return created
    
    def create_all_from_json(
        self,
        config_dir: str = "config"
    ) -> Dict[str, List[str]]:
        """
        Load configuration from JSON files and create all objects
        
        Args:
            config_dir: Directory containing JSON configuration files
            
        Returns:
            Dictionary with lists of created object names
        """
        # Load scope configuration
        scope_config = ConfigLoader.load_scope_config(
            os.path.join(config_dir, "scope.json")
        )
        
        scope_type = ScopeType(scope_config.get('type', 'folder'))
        scope_value = scope_config.get('value', 'All')
        
        self.logger.info(f"🚀 Starting bulk creation with scope: {scope_type.value}={scope_value}")
        
        # Load and create objects
        objects_data = ConfigLoader.load_objects(
            os.path.join(config_dir, "objects.json")
        )
        if objects_data:
            self.create_objects(objects_data, scope_type, scope_value)

        # Load and create security rules
        rules = ConfigLoader.load_security_rules(
            os.path.join(config_dir, "rules.json")
        )
        if rules:
            self.create_security_rules(rules, scope_type, scope_value)
        
        return self.created_objects
    
    def get_summary(self) -> Dict[str, int]:
        """
        Get summary of created objects
        
        Returns:
            Dictionary with counts of created objects
        """
        return {key: len(value) for key, value in self.created_objects.items()}
    
    def print_summary(self) -> None:
        """Print a formatted summary of created objects"""
        summary = self.get_summary()
        total = sum(summary.values())
        
        self.logger.info("\n📊 CREATION SUMMARY")
        self.logger.info("=" * 50)
        self.logger.info(f"  Address Objects:     {summary['addresses']:>5}")
        self.logger.info(f"  Address Groups:      {summary['address_groups']:>5}")
        self.logger.info(f"  URL Categories:      {summary['url_categories']:>5}")
        self.logger.info(f"  Security Rules:      {summary['security_rules']:>5}")
        self.logger.info("-" * 50)
        self.logger.info(f"  TOTAL OBJECTS:       {total:>5}")
        self.logger.info("=" * 50)


# ============================================================
# MAIN EXECUTION
# ============================================================

def main():
    """
    Main function demonstrating JSON-driven approach
    """
    
    # Configuration
    CLIENT_ID = os.environ.get("SCM_CLIENT_ID", "your_client_id")
    CLIENT_SECRET = os.environ.get("SCM_CLIENT_SECRET", "your_client_secret")
    TSG_ID = os.environ.get("SCM_TSG_ID", "your_tsg_id")
    CONFIG_DIR = os.environ.get("SCM_CONFIG_DIR", "config")
    
    # Initialize manager
    manager = SCMObjectManager(CLIENT_ID, CLIENT_SECRET, TSG_ID)
    
    # Create all objects from JSON files
    results = manager.create_all_from_json(CONFIG_DIR)
    
    # Print summary
    manager.print_summary()
    
    # Print detailed results
    if any(results.values()):
        print("\n📋 DETAILED RESULTS:")
        for category, items in results.items():
            if items:
                print(f"  {category.replace('_', ' ').title()}: {', '.join(items)}")


if __name__ == "__main__":
    main()
