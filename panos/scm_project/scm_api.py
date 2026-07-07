#!/usr/bin/env python3
"""
PAN Strata Cloud manager (SCM)
This script configures interfaces, logical router, 
and BGP routing on PA NGFW managed by SCM
"""

import time
import json
import requests
import logging
import sys
import json
import os
from enum import Enum
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass, asdict
import logging

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
        """Convert string to ScopeType with validation"""
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
                 scope: Union[Dict, ScmScope], config: Optional[ApiConfig] = None):

        self.client_id = client_id
        self.client_secret = client_secret
        self.tsg_id = tsg_id
        self.config = ApiConfig()

        if isinstance(scope, dict):
            try:
                scope_type = ScopeType.from_string(scope.get("type"))
                self.scope = ScmScope(scope_type, scope.get("value"))
            except ValueError as e:
                logger.error(f"Invalid scope: {e}")
                sys.exit(0)
        else:
            logger.info("Error: Scope is not valid!")
            sys.exit(0)

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
        
        logger.info(f"SCM API initialized with scope: {self.scope.type.value}={self.scope.value}")

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
        """
        Make an API request to SCM.
        """
    
        url = f"https://{self.config.host}{endpoint}"

        try:
            token = self.get_token()
            headers = {
                "Authorization": f"Bearer {token}"
            }
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

    def create_object(self, object_type: str, data: Dict) -> Dict:
        """Create a single object"""
        try:
            endpoint = f"/config/network/v1/{object_type}"
            data.update({self.scope.to_dict().get('type'): self.scope.to_dict().get('value')})
            logger.info(f"Creating {object_type}-{data.get('name')} in {self.scope.to_dict().get('type')}-{self.scope.to_dict().get('value')}")
            return self._make_api_request("POST", endpoint, data=data)

        except Exception as e:
            logger.error(f"Failed to create network configuration: {e}")
            return []

    def list_object(self, object_type: str, name = str, limit: int = 200, offset: int = 0) -> List[Dict]:
        """Retrieve a single object"""
        endpoint = f"/config/network/v1/{object_type}"
        params = self.scope.to_params()
        params.update({"name": name})
        params.update({"limit": limit, "offset": offset})
    
        try:
            logger.info(f"Fetching {object_type}-{name} in {self.scope.to_dict().get('type')}-{self.scope.to_dict().get('value')}")
            response = self._make_api_request("GET", endpoint, params=params)

            return response.get("data", [])

        except Exception as e:
            logger.error(f"Failed to retrieve network configuration: {e}")
            return []

    def bulk_operation(self, operation: OperationType, config_data: Dict) -> List[Dict]:
        """
        Create/update/delete/list objects in a specific scope.
        
        Args:
            operation: Operation method for objects in a scope
            Object_data: Dict of object data
        
        Returns:
            List of configurations
        """

        results = []
        ops = OperationType.from_string(operation)

        if operation == OperationType.LIST.value:
            for object_type, objects in config_data.items():
                for obj in objects:
                    name = obj.get('name')
                    response = self.list_object(object_type, name)
                    results.extend(response)

        elif operation == OperationType.CREATE.value:
            for object_type, objects in config_data.items():
                for obj in objects:
                    response = self.create_object(object_type, obj)
                    results.append(response)
    
        return results

def get_secret(vault, vaultpath):
    from encryption import CredentialManager
    manager = CredentialManager(vault, vaultpath)
    credentails = manager.decrypt()
    return credentails

def parse_arguments():
    import argparse
    """Parse command line arguments."""

    parser = argparse.ArgumentParser(
        description="Create/delete/list NGFW configuration in SCM scope"
    )
    
    # Common arguments
    #parser.add_argument("--username", "-u", type=str,
    #                    help="SCM client identifier")
    parser.add_argument("--file", "-f", type=str,
                        help="Object configuration JSON file")
    parser.add_argument("--operation", "-o", choices=['create', 'delete', 'list'], 
                        nargs="?", const="list", default='list',
                        help="Operation commands to create/delete/list configuration in SCM scope. Default to 'list'")

    # Search arguments
    group = parser.add_argument_group(title="List configuration in SCM scope")
    group.add_argument("--scope", "-s", nargs=2,
                        help="Scope to search. 'type' 'name'")
    group.add_argument("--search", nargs=2,
                        help="Object to search. 'endpoint' 'name'")

    return parser.parse_args()

# ==================== Main Execution ====================

def main():
    """
    Main function run SCM API.
    """

    args = parse_arguments()

    basepath = Path.home() / 'pyenv3.9' / 'panos' / 'scm_project'
    filepath = f"{basepath}/config/{args.file}"
    vaultpath = Path.home() / 'pyenv3.9' / 'secrets'

    VAULT = "panos_secrets.bin"
    SCOPE = {}
    config_data = {}

    CLIENT_ID = "tyu-API@1533830390.iam.panserviceaccount.com"
    TSG_ID = "tsg_id:1533830390"
    credentails = get_secret(VAULT, vaultpath)
    CLIENT_SECRET = credentails.get(CLIENT_ID)
    OPERATION = args.operation

    if os.path.isfile(filepath):
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            configdata = json.load(f)
        SCOPE = configdata.get("scope")
        config_data = {k: v for k, v in configdata.items() if k != "scope"}
    elif args.scope and args.search:
        SCOPE = {"type": args.scope[0], "value": args.scope[1]}
        config_data = {args.search[0]: [{"name": args.search[1]}]}
    else:
        logger.info("Error: Scope and endpoint must be provided!")
        sys.exist(0)
    
    scm_client = ScmAPI(CLIENT_ID, CLIENT_SECRET, TSG_ID, SCOPE)
    if config_data:
        output = scm_client.bulk_operation(OPERATION, config_data)
        
        print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()
