#!/usr/bin/env python3
"""
PAN Strata Cloud Manager (SCM)
This script configures interfaces, logical router, BGP routing,
objects, and security rules on PA NGFW managed by SCM.
"""

import time
import json
import requests
import logging
import sys
import os
from enum import Enum
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass, asdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class OperationType(Enum):
    """Supported operation types"""
    CREATE = "create"
    DELETE = "delete"
    LIST = "list"
    UPDATE = "update"
    
    @classmethod
    def from_string(cls, value: str) -> 'OperationType':
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(f"Invalid operation: {value}. Must be 'create', 'delete', 'list', or 'update'")


@dataclass
class ApiConfig:
    """API configuration settings"""
    host: str = "api.strata.paloaltonetworks.com"
    token_url: str = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
    timeout: int = 30


class ScopeType(Enum):
    """Configuration scope types in SCM"""
    FOLDER = "folder"
    SNIPPET = "snippet"
    DEVICE = "device"
    @classmethod
    def from_string(cls, value: str) -> 'ScopeType':
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(f"Invalid scope type: {value}. Must be 'folder', 'snippet', or 'device'")


@dataclass
class ScmScope:
    """SCM configuration scope"""
    type: ScopeType
    value: str
    def to_dict(self) -> Dict[str, str]:
        return {"type": self.type.value, "value": self.value}
    def to_params(self) -> Dict[str, str]:
        return {self.type.value: self.value}


class ScmAPI:
    def __init__(self, client_id: str, client_secret: str, tsg_id: str,
                config: Optional[ApiConfig] = None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.tsg_id = tsg_id
        self.config = config or ApiConfig()

        self.scope = None

        self.token_cache = {
            "access_token": None,
            "expires_at": 0
        }

        # Session for connection pooling
        self._session = requests.Session()
        self._session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json"
        })
        
        logger.info(f"SCM API initialized")

    def _get_scope(self, scope: Union[Dict, ScmScope]) -> str:
        if isinstance(scope, dict):
            try:
                scope_type = ScopeType.from_string(scope.get("type"))
                self.scope = ScmScope(scope_type, scope.get("value"))
                return True
            except ValueError as e:
                return False
        elif isinstance(scope, ScmScope):
            self.scope = scope
            return True
        else:
            return False

    def _get_endpoint(self, object_type: str) -> str:
        """
        Determine the correct API base path based on object type.
        """
        # List of network types
        network_types = {
            "ethernet-interfaces", "aggregate-interfaces", "layer3-subinterfaces", "zones",
            "interface-management-profiles", "route-prefix-lists", "route-community-lists",
            "logical-routers", "bgp-address-family-profiles", "bgp-filtering-profiles", 
            "bgp-redistribution-profiles", "bgp-route-maps", "bgp-route-map-redistributions",
            "nat-rules"
        }
        # List of object types
        object_types = {
            "addresses", "address-groups", "services", "service-groups", "external-dynamic-lists"
        }
        # List if security types
        security_types = {
            "security-rules", "url-categories"
        }

        if object_type in network_types:
            return f"/config/network/v1/{object_type}"
        elif object_type in object_types:
            return f"/config/objects/v1/{object_type}"
        elif object_type in security_types:
            return f"/config/security/v1/{object_type}"
        else:
            return None

    def get_token(self) -> Optional[str]:
        """Generate or retrieve cached access token for SCM"""
        if self.token_cache["access_token"] and time.time() < self.token_cache["expires_at"] - 60:
            return self.token_cache["access_token"]
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
    
        try:
            response = requests.post(
                self.config.token_url,
                headers=headers,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": self.tsg_id
                },
                timeout=30
            )
            response.raise_for_status()
            
            token_data = response.json()
            self.token_cache["access_token"] = token_data["access_token"]
            self.token_cache["expires_at"] = time.time() + token_data["expires_in"]
            
            logger.info("Access token obtained successfully")
            return self.token_cache["access_token"]
    
        except requests.RequestException as e:
            logger.error(f"Token retrieval failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Status: {e.response.status_code}, Body: {e.response.text}")
            return None
    
    def _make_api_request(self, method: str, endpoint: str, data: Optional[Dict] = None,
                          params: Optional[Dict] = None) -> Dict:
        """Make an API request to SCM."""
        url = f"https://{self.config.host}{endpoint}"

        try:
            token = self.get_token()
            headers = {"Authorization": f"Bearer {token}"}
            response = self._session.request(
                method=method,
                url=url,
                headers=headers,
                json=data,
                params=params,
                timeout=self.config.timeout
            )
            response.raise_for_status()
            return response.json() if response.content else {}
    
        except requests.RequestException as e:
            logger.error(f"API request failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Status: {e.response.status_code}")
                logger.error(f"Response: {e.response.text}")
            raise

    def create_object(self, endpoint: str, data: Dict) -> Dict:
        """Create a single object (network or security)."""
        try:
            cfg_data = {k: v for k,v in data.items() if v}
            cfg_data.update(self.scope.to_params())
            logger.info(f"Creating {data.get('name')} in {self.scope.type.value}={self.scope.value}")
            return self._make_api_request("POST", endpoint, data=cfg_data)
        except Exception as e:
            logger.error(f"Failed to create {data.get('name')}: {e}")
            return {}

    def update_object(self, endpoint: str, data: Dict) -> Dict:
        """Update a single object (network or security)."""
        try:
            params = {k: v for k,v in data.items() if k == 'name' or k == 'position'}
            params.update(self.scope.to_params())

            new_data = {k: v for k,v in data.items() if v}
            new_data.update(self.scope.to_params())
            existing = self.list_object(endpoint, params)
            if existing:
                uuid = existing.get('data')[0].get("id") if 'data' in existing else existing.get("id")
                new_endpoint = f"{endpoint}/{uuid}"
                logger.info(f"Updating {data.get('name')} in {self.scope.type.value}={self.scope.value}")
                return self._make_api_request("PUT", new_endpoint, data=new_data)
            else:
                logger.warning(f"'{data.get('name')}' not found for updating")
                return {}
        except Exception as e:
            logger.error(f"Failed to update {data.get('name') }: {e}")
            return {}

    def delete_object(self, endpoint: str, params: Dict) -> Dict:
        """Delete a single object by name."""
        try:
            existing = self.list_object(endpoint, params)
            if existing:
                uuid = existing.get('data')[0].get("id") if 'data' in existing else existing.get("id")
                new_endpoint = f"{endpoint}/{uuid}"
                logger.info(f"Deleting {params.get('name')} in {self.scope.type.value}={self.scope.value}")
                return self._make_api_request("DELETE", new_endpoint)
            else:
                logger.warning(f"'{params.get('name')}' not found for deletion")
                return {}
        except Exception as e:
            logger.error(f"Failed to delete {params.get('name')}: {e}")
            return {}

    def list_object(self, endpoint: str, params: Dict = None,
                    limit: int = 200, offset: int = 0) -> List[Dict]:
        """Retrieve objects of a given type, optionally filtered by name."""

        params.update(self.scope.to_params())
        params.update({"limit": limit, "offset": offset})
    
        try:
            logger.info(f"Fetching {params.get('name')} in {self.scope.type.value}={self.scope.value}")
            response = self._make_api_request("GET", endpoint, params=params)
            return response
        except Exception as e:
            logger.error(f"Failed to find {params.get('name')}: {e}")
            return []

    def bulk_operation(self, operation: OperationType, config_data: Dict) -> List[Dict]:
        """
        Perform bulk create/update/delete/list on multiple object types.
        config_data: dict with object_type as key and list of objects as value.
        """
        results = []

        for scope_name, data in config_data.items():
            scope = {
                "type": data.get('type'),
                "value": scope_name
            }
            if not self._get_scope(scope):
                logger.error(f"Invalid configuration scope: {data.get('type')}: '{scope_name}'")
                continue

            object_data = {k: v for k,v in data.items() if k != "type"}

            if any(operation == op for op in [OperationType.CREATE, OperationType.UPDATE, OperationType.LIST]):
                if "ethernet-interfaces" in object_data:
    
                    endpoint = self._get_endpoint("ethernet-interfaces")
                    for obj in object_data.get("ethernet-interfaces"):
                        if operation == OperationType.CREATE:
                            resp = self.create_object(endpoint, obj)
                        elif operation == OperationType.UPDATE:
                            resp = self.update_object(endpoint, obj)
                        elif operation == OperationType.LIST:
                            name = obj.get("name")
                            if not name:
                                logger.error(f"Cannot search interface: object missing 'name'")
                                continue
                            params = {k: v for k,v in obj.items() if k == 'name' or k == 'position'}
                            resp = self.list_object(endpoint, params)
        
                        results.append(resp)
    
                if "layer3-subinterfaces" in object_data:
    
                    endpoint = self._get_endpoint("layer3-subinterfaces")
                    for obj in object_data.get("layer3-subinterfaces"):
                        if operation == OperationType.CREATE:
                            resp = self.create_object(endpoint, obj)
                        elif operation == OperationType.UPDATE:
                            resp = self.update_object(endpoint, obj)
                        elif operation == OperationType.LIST:
                            name = obj.get("name")
                            if not name:
                                logger.error(f"Cannot search subinterface: object missing 'name'")
                                continue
                            params = {k: v for k,v in obj.items() if k == 'name' or k == 'position'}
                            resp = self.list_object(endpoint, params)
        
                        results.append(resp)
    
                if "logical-routers" in object_data:
    
                    endpoint = self._get_endpoint("logical-routers")
                    for obj in object_data.get("logical-routers"):
                        if operation == OperationType.CREATE:
                            resp = self.create_object(endpoint, obj)
                        elif operation == OperationType.UPDATE:
                            resp = self.update_object(endpoint, obj)
                        elif operation == OperationType.LIST:
                            name = obj.get("name")
                            if not name:
                                logger.error(f"Cannot search logical router: object missing 'name'")
                                continue
                            params = {k: v for k,v in obj.items() if k == 'name' or k == 'position'}
                            resp = self.list_object(endpoint, params)
        
                        results.append(resp)
    
                if "zones" in object_data:
    
                    endpoint = self._get_endpoint("zones")
                    for obj in object_data.get("zones"):
                        if operation == OperationType.CREATE:
                            resp = self.create_object(endpoint, obj)
                        elif operation == OperationType.UPDATE:
                            resp = self.update_object(endpoint, obj)
                        elif operation == OperationType.LIST:
                            name = obj.get("name")
                            if not name:
                                logger.error(f"Cannot search zone: object missing 'name'")
                                continue
                            params = {k: v for k,v in obj.items() if k == 'name' or k == 'position'}
                            resp = self.list_object(endpoint, params)

                        results.append(resp)
    
                if "addresses" in object_data:
    
                    endpoint = self._get_endpoint("addresses")
                    for obj in object_data.get("addresses"):
                        if operation == OperationType.CREATE:
                            resp = self.create_object(endpoint, obj)
                        elif operation == OperationType.UPDATE:
                            resp = self.update_object(endpoint, obj)
                        elif operation == OperationType.LIST:
                            name = obj.get("name")
                            if not name:
                                logger.error(f"Cannot search address: object missing 'name'")
                                continue
                            params = {k: v for k,v in obj.items() if k == 'name' or k == 'position'}
                            resp = self.list_object(endpoint, params)

                        results.append(resp)
    
                if "security-rules" in object_data:
    
                    endpoint = self._get_endpoint("security-rules")
                    for obj in object_data.get("security-rules"):
                        if operation == OperationType.CREATE:
                            resp = self.create_object(endpoint, obj)
                        elif operation == OperationType.UPDATE:
                            resp = self.update_object(endpoint, obj)
                        elif operation == OperationType.LIST:
                            name = obj.get("name")
                            if not name:
                                logger.error(f"Cannot search security rule: object missing 'name'")
                                continue
                            params = {k: v for k,v in obj.items() if k == 'name' or k == 'position'}
                            resp = self.list_object(endpoint, params)

                        results.append(resp)

            elif operation == OperationType.DELETE:
                if "logical-routers" in object_data:
    
                    endpoint = self._get_endpoint("logical-routers")
                    for obj in object_data.get("logical-routers"):
                        name = obj.get("name")
                        if not name:
                            logger.error(f"Cannot delete logical router: object missing 'name'")
                            continue
                        params = {k: v for k,v in obj.items() if k == 'name' or k == 'position'}
                        resp = self.delete_object(endpoint, params)
        
                        results.append(resp)
    
                if "zones" in object_data:
    
                    endpoint = self._get_endpoint("zones")
                    for obj in object_data.get("zones"):
                        name = obj.get("name")
                        if not name:
                            logger.error(f"Cannot delete zone: object missing 'name'")
                            continue
                        params = {k: v for k,v in obj.items() if k == 'name' or k == 'position'}
                        resp = self.delete_object(endpoint, params)

                        results.append(resp)

                if "layer3-subinterfaces" in object_data:
    
                    endpoint = self._get_endpoint("layer3-subinterfaces")
                    for obj in object_data.get("layer3-subinterfaces"):
                        name = obj.get("name")
                        if not name:
                            logger.error(f"Cannot delete subinterface: object missing 'name'")
                            continue
                        params = {k: v for k,v in obj.items() if k == 'name' or k == 'position'}
                        resp = self.delete_object(endpoint, params)
        
                        results.append(resp)

                if "ethernet-interfaces" in object_data:
    
                    endpoint = self._get_endpoint("ethernet-interfaces")
                    for obj in object_data.get("ethernet-interfaces"):
                        name = obj.get("name")
                        if not name:
                            logger.error(f"Cannot delete interface: object missing 'name'")
                            continue
                        params = {k: v for k,v in obj.items() if k == 'name' or k == 'position'}
                        resp = self.delete_object(endpoint, params)
        
                        results.append(resp)

                if "security-rules" in object_data:
    
                    endpoint = self._get_endpoint("security-rules")
                    for obj in object_data.get("security-rules"):
                        name = obj.get("name")
                        if not name:
                            logger.error(f"Cannot delete security rule: object missing 'name'")
                            continue
                        params = {k: v for k,v in obj.items() if k == 'name' or k == 'position'}
                        resp = self.delete_object(endpoint, params)

                        results.append(resp)

                if "addresses" in object_data:
    
                    endpoint = self._get_endpoint("addresses")
                    for obj in object_data.get("addresses"):
                        name = obj.get("name")
                        if not name:
                            logger.error(f"Cannot delete address: object missing 'name'")
                            continue
                        params = {k: v for k,v in obj.items() if k == 'name' or k == 'position'}
                        resp = self.delete_object(endpoint, params)

                        results.append(resp)

        return results

def get_secret(vault, vaultpath):
    from encryption import CredentialManager
    manager = CredentialManager(vault, vaultpath)
    credentials = manager.decrypt()
    return credentials


def parse_arguments():
    import argparse
    parser = argparse.ArgumentParser(
        description="Create/delete/list NGFW configuration in SCM scope"
    )
    parser.add_argument("--file", "-f", type=str,
                        help="Object configuration JSON file")
    parser.add_argument("--operation", "-o", choices=['create', 'update', 'delete', 'list'],
                        nargs="?", const="list", default='list',
                        help="Operation command to perform. Default: 'list'")

    group = parser.add_argument_group(title="List configuration in SCM scope")
    group.add_argument("--scope", "-s", nargs=2,
                       help="Scope to search. 'type' 'name'")
    group.add_argument("--search", nargs=2,
                       help="Object to search. 'endpoint' 'name'")

    return parser.parse_args()


def main():
    args = parse_arguments()

    basepath = Path.home() / 'pyenv3.9' / 'panos' / 'scm_project'
    filepath = f"{basepath}/config/{args.file}"
    vaultpath = Path.home() / 'pyenv3.9' / 'secrets'

    VAULT = "panos_secrets.bin"
    CLIENT_ID = ""
    TSG_ID = "tsg_id:"
    credentials = get_secret(VAULT, vaultpath)
    CLIENT_SECRET = credentials.get(CLIENT_ID)

    config_data = {}

    if os.path.isfile(filepath):
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            config_data = json.load(f)

    if not config_data:
        logger.error("Missing the configuration scope and/or objects.")
        sys.exit()

    try:
        OPERATION = OperationType.from_string(args.operation)
    except:
        logger.error(f"Invalid operation command: {args.operation}")
        sys.exit()

    scm_client = ScmAPI(CLIENT_ID, CLIENT_SECRET, TSG_ID)
    output = scm_client.bulk_operation(OPERATION, config_data)

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
