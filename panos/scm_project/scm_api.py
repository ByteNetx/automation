#!/usr/bin/env python3
"""
PAN Strata Cloud manager (SCM)
This script configures ethernet interfaces, logical router, 
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
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ScopeType(Enum):
    """Configuration scope types in SCM"""
    FOLDER = "folder"
    SNIPPET = "snippet"
    DEVICE = "device"

class ScmAPI:

    def __init__(self, client_id: str, client_secret: str, tsg_id: str,
                 scope: Dict, **kwargs):

        self.host = "api.strata.paloaltonetworks.com"
        self.client_id = client_id
        self.client_secret = client_secret
        self.tsg_id = tsg_id
        
        try:
            self.scope_type = ScopeType(scope.get("type", "folder"))
            self.scope_value = scope.get("value", "All Firewall")
        except:
            logger.info("Error: Invalid scope! Must be 'folder', 'snippet', or 'device'.")
            sys.exit(0)

        self.token_cache = {
            "access_token": None,
            "expires_at": 0
        }

        self.token = self.get_token()

    def get_token(self) -> Optional[str]:
        """Generate an access token for SCM."""
        TOKEN_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
        if self.token_cache["access_token"] and time.time() < self.token_cache["expires_at"] - 60:
            return self.token_cache["access_token"]
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
    
        try:
            response = requests.post(
                TOKEN_URL,
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
    
    def _make_api_request(self, method: str, endpoint: str, data: Dict = None, params: Dict = None) -> Dict:
        """
        Make an API request to SCM with automatic token handling.
        """
        token = self.token
        
        url = f"https://{self.host}{endpoint}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        try:
            logger.debug(f"Making {method} request to {endpoint}")
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=data,
                params=params,
                timeout=60
            )
            response.raise_for_status()
            return response.json() if response.content else {}
        
        except requests.RequestException as e:
            logger.error(f"API request failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Status: {e.response.status_code}")
                logger.error(f"Response: {e.response.text}")
            raise

    
    def retrieve_config(self, object_data: Dict, limit: int = 200, offset: int = 0) -> List[Dict]:
        """
        Retreive objects in a specific scope.
        
        Args:
            Object_data: Dict of object data
            limit: Maximum number of results per page
            offset: Pagination offset
        
        Returns:
            List of configurations
        """
        scope_type = self.scope_type
        scope_value = self.scope_value
        results = []
    
        try:
            for key , values in object_data.items():
                endpoint = f"/config/network/v1/{key}"
                for value in values:
                    params = {
                        scope_type: scope_value,
                        "name": value,
                        "limit": limit,
                        "offset": offset
                    }
                
                    
                    logger.info(f"Fetching {key}: {value} from {scope_type}: {scope_value}")
                    response = self._make_api_request("GET", endpoint, params=params)
                    
                    # The response might have 'data' key containing the list
                    results.append(response.get("data", []))
    
            return results
    
        except Exception as e:
            logger.error(f"Failed to retrieve network configuration: {e}")
            return []

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
    parser.add_argument("--username", "-u", type=str,
                        help="SCM client identifier")
    parser.add_argument("--file", "-f", type=str,
                        help="Object configuration JSON file")
    parser.add_argument("--operation", "-o", choices=['create', 'delete', 'list'], 
                        nargs="?", const="list", default='list',
                        help="Operation commands to create/delete/list configuration in SCM scope. Default to 'list'")

    # Search arguments
    group = parser.add_argument_group(title="List configuration in SCM scope")
    group.add_argument("--scope", "-s", narg=2,
                        help="Scope to search. 'type' 'name'")
    group.add_argument("--search", narg=2,
                        help="Object to search. 'endpoint' 'name'")

# ==================== Main Execution ====================

def main():
    """
    Main function run SCM Rest API.
    """

    args = parse_arguments()

    basepath = Path.home() / 'pyenv3.13' / 'panos' / 'pano_project'
    filepath = f"{basepath}/config/{args.file}"
    vaultpath = Path.home() / 'pyenv3.13' / 'secrets'

    VAULT = "secrets.bin"
    SCOPE = {}
    config_data = {}
    results = []

    CLIENT_ID = args.username
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

    if SCOPE:
        scmapi = ScmAPI(CLIENT_ID, CLIENT_SECRET, SCOPE)
    if config_data:
        if any(OPERATION == op for op in ['list', 'search']):
            # ==================== DISPLAY OBJECTS ====================
            logger.info(f"Searching objects in device group '{DEVICE_GROUP}':")
            logger.info("=" * 60)
            output = scmapi.retrieve_config(config_data)
    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()
