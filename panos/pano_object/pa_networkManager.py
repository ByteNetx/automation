#!/usr/bin/env python3
"""
PAN-OS Python SDK Script to manage Layer3 Subinterface and Virtual-Router

"""

import logging
import sys
import json
import os
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from enum import Enum
from panos import firewall, network
from panos.errors import PanDeviceError

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

class PANetworkManager:
    """
    A class to manage Layer3 subinterfaces and virtual-router on PAN-OS NGFW.

    """
    
    def __init__(self, hostname: str, username: str=None, password: str=None,
                api_key: str=None, vsys: str=None, commit_changes: bool=False, **kwargs):

        """
        Initialize the PANetworkManager.
        
        Args:
            host: Firewall IP or hostname
            username: Username for authentication (optional if api_key provided)
            password: Password for authentication (optional if api_key provided)
            api_key: API key for authentication (optional)
            vsys: The vsys of this firewall
            commit_changes: Whether to commit changes
        """
        self.hostname = hostname
        self.username = username
        self.commit_changes = commit_changes
        self.vsys = vsys

        self.created_objects = []
        self.existing_objects = []

        
        # Initialize firewall connection
        if vsys:
            if api_key:
                self.fw = firewall.Firewall(hostname, api_key=api_key, vsys=vsys)
            elif username and password:
                self.fw = firewall.Firewall(hostname, api_username=username, api_password=password, vsys=vsys)
        else:
            if api_key:
                self.fw = firewall.Firewall(hostname, api_key=api_key)
            elif username and password:
                self.fw = firewall.Firewall(hostname, api_username=username, api_password=password)
    
        self.fw.refresh_system_info()
        logger.info(f"Connected to: {self.fw.hostname} (PAN-OS {self.fw.version})")

    def check_virtual_router_exists(self, virtual_router_name: str) -> Tuple[bool, Optional[network.VirtualRouter]]:
        """
        Check if a virtual router already exists on the firewall.

        Returns:
            Tuple[bool, Optional[network.VirtualRouter]]: (exists, virtual_router_object)
        """
        try:

            virtual_router = network.VirtualRouter(name=virtual_router_name)

            self.fw.add(virtual_router)
            
            # Try to refresh from firewall
            virtual_router.refresh(self.fw)
            self.existing_objects.append(('virtual_router', virtual_router.name))
            return True, virtual_router
            
        except PanDeviceError as e:
            # Virtual router does not exist
            logger.info(f"Virtual router {virtual_router_name} does not exist: {e}")
            return False, None

    def check_zone_exists(self, zone_name) -> Tuple[bool, Optional[network.Zone]]:
        """
        Check if a zone already exist on the firewall.

        Returns:
            Optional[network.Zone]: The zone object
        """
        try:
            zone = network.Zone(name=zone_name)
            self.fw.add(zone)

            zone.refresh(self.fw)
            self.existing_objects.append(('zone', zone.name))

            return True, zone
            
        except:
            logger.info(f"Zone {zone_name} does not exist")
            return False, None

    def check_redist_profile_exists(self, virtual_router_name: str, redist_profile_name: str) -> Tuple[bool, Optional[network.RedistributionProfile]]:
        """
        Check if a redistribution profile already exists on the virtual router.
    
        Returns:
            Tuple[bool, Optional[network.RedistributionProfile]]: (exists, redist_profile_object)
        """
        try:
            
            exists, virtual_router = self.check_virtual_router_exists(virtual_router_name)
    
            if not exists:
                return None
    
            redist_profile = network.RedistributionProfile(name=redist_profile_name)
            virtual_router.add(redist_profile)
            
            # Try to refresh from firewall
            redist_profile.refresh(virtual_router)
            self.existing_objects.append(('redist_profile', redist_profile.name))
            return True, redist_profile
            
        except PanDeviceError as e:
            # Redistribution profile does not exist
            logger.info(f"Redistribution profile {redist_profile_name} does not exist: {e}")
            return False, None

    def check_parent_interface_exists(self, interface_name: str) -> Tuple[bool, Optional[network.Interface]]:
        """
        Check if a parent interface exists on the firewall.

        Returns:
            Tuple[bool, Optional[network.Interface]]: (exists, interface_object)
        """
        try:
            
            # Create interface object
            if interface_name.startswith("ae"):
                parent_interface = network.AggregateInterface(interface_name)
            else:
                parent_interface = network.EthernetInterface(interface_name)
            
            # Try to refresh the interface from the firewall
            self.fw.add(parent_interface)
            parent_interface.refresh(self.fw)
            self.existing_objects.append(('parent_interface', parent_interface.name))
            return True, parent_interface
            
        except PanDeviceError as e:
            # Parent interface doesn't exist
            logger.info(f"Parent interface {interface_name} does not exist: {e}")
            return False, None
    
    def create_parent_interface(self, parent_interface_name: str, mode: str) -> Optional[network.Interface]:
        """
        Create a parent interface on the firewall.

        Returns: 
            Optional[network.Interface]: The interface object
        """

        try:
            if parent_interface_name.startswith("ae"):
                existing_parent_intf = network.AggregateInterface(parent_interface_name)
            else:
                existing_parent_intf = network.EthernetInterface(parent_interface_name)
            self.fw.add(existing_parent_intf)
            existing_parent_intf.refresh(self.fw)
            logger.info(f"Interface {existing_parent_intf.name} already exist")
            self.existing_objects.append(('parent_interface', existing_parent_intf.name))

            return existing_parent_intf

        except PanDeviceError as e:
            logger.info(f"Interface {parent_interface_name} does not exist, creating...")

            if parent_interface_name.startswith("ae"):
                new_parent_intf = network.AggregateInterface(name=parent_interface_name, mode=mode)
            else:
                new_parent_intf = network.EthernetInterface(name=parent_interface_name, mode=mode)
            self.fw.add(new_parent_intf)
            new_parent_intf.create()
            self.created_objects.append(('Interface', new_parent_intf.name))

            return new_parent_intf

    def create_subinterface(self, parent_interface: network.Interface, intf_params: Dict) -> Optional[network.Layer3Subinterface]:
           
        if not parent_interface:
            return False
        tag = intf_params.get('tag')
        subinterface_name = f"{parent_interface.name}.{tag}"
        try:
            existing_subif = network.Layer3Subinterface(subinterface_name)
            parent_interface.add(existing_subif)
            existing_subif.refresh(parent_interface)
            logger.info(f"Layer3 subinterface {existing_subif.name} already exists, updating...")
            self.existing_objects.append(('layer3_subinterface', existing_subif.name))
            for key, value in intf_params.items():
                if hasattr(existing_subif, key):
                    setattr(existing_subif, key, value)                
            existing_subif.apply()
            if not existing_subif:
                return False
        except:
            logger.info(f"Subinterface {subinterface_name} does not exist, creating...")

            new_params = {"name": subinterface_name}
            new_params.update(intf_params)
            new_subif = network.Layer3Subinterface(**new_params)

            parent_interface.add(new_subif)
            
            new_subif.create()
        
            self.created_objects.append(('layer3_subinterface', new_subif.name))
            if not new_subif:
                return False

        return True

    def create_zone(self, name, zone_params: Dict) -> bool:
        """
        Create a zone on the firewall

        Returns:
            Optional[network.Zone]: The zone object
        """

        try:

            existing_zone = network.Zone(name=name)
            self.fw.add(existing_zone)
            existing_zone.refresh(self.fw)
            logger.info(f"Zone '{existing_zone.name}' already exist, updating...")
            self.existing_objects.append(('zone', existing_zone.name))

            for key, value in zone_params.items():
                if hasattr(existing_zone, key):
                    setattr(existing_zone, key, value)

            existing_zone.apply()

            if not existing_zone:
                return False

        except:
            logger.info(f"Zone '{name}' does not exist, creating...")
            new_params = {"name": name}
            new_params.update(zone_params)
            new_zone = network.Zone(**new_params)
            self.fw.add(new_zone)
            new_zone.create()
            self.created_objects.append(('zone', new_zone.name))

            if not new_zone:
                return False

        return True
    
    def create_virtual_router(
        self,
        name: str,
        interface: List
    ) -> Optional[network.VirtualRouter]:
        """
        Create a virtual router on the firewall.

        Returns:
            Optional[network.VirtualRouter]: The virtual router object
        """

        try:
            existing_vr = network.VirtualRouter(name)
            self.fw.add(existing_vr)
            existing_vr.refresh(self.fw)
            logger.info(f"Virtual router '{existing_vr.name}' already exist, updating...")
            self.existing_objects.append(('virtual_router', existing_vr.name))

            setattr(existing_vr, 'interface', interface)
            existing_vr.apply()

            return existing_vr
        except:
            logger.info(f"Virtual router '{name}' does not exist, creating...")
            new_vr = network.VirtualRouter(name=name, interface=interface)
            self.fw.add(new_vr)
            new_vr.create()
            self.created_objects.append(('virtual_router', new_vr.name))

            return new_vr

    def create_static_route(
        self,
        virtual_router: network.VirtualRouter,
        name: str,
        static_route_params: Dict
    ) -> bool:
        """
        Create/update static route in the virtual router.

        Returns:
            Bool
        """

        if not virtual_router:
            logger.error(f"Invalid virtual router provided")
            return None
        try:
            existing_static_route = network.StaticRoute(name)
            virtual_router.add(existing_static_route)
            existing_static_route.refresh(virtual_router)
            logger.info(f"Static route '{existing_static_route.name}' already exists, updating...")
            self.existing_objects.append(('static_route', existing_static_route.name))

            for key, value in static_route_params.items():
                if hasattr(existing_static_route, key):
                    setattr(existing_static_route, key, value)

            existing_static_route.apply()

            if not existing_static_route:
                return False
        except:
            logger.info(f"Static route '{name}' does not exist, creating...")
            new_params = {"name": name}
            new_params.update(static_route_params)
            new_static_route = network.StaticRoute(**new_params)
            virtual_router.add(new_static_route)
            new_static_route.create()
            self.created_objects.append(('static_route', new_static_route.name))

            if not new_static_route:
                return False
        
        return True

    def create_redist_profile(
        self,
        virtual_router: network.VirtualRouter,
        name: str,
        redist_profile_params: Dict
    ) -> bool:
        """
        Create/update redistribution profile.

        Returns:
            Bool
        """

        if not virtual_router:
            logger.error(f"Invalid virtual router provided")
            return None
        try:
            existing_redist_profile = network.RedistributionProfile(name)
            virtual_router.add(existing_redist_profile)
            existing_redist_profile.refresh(virtual_router)
            logger.info(f"Redistribution profile '{existing_redist_profile.name}' already exists, updating...")
            self.existing_objects.append(('redist_profile', existing_redist_profile.name))

            for key, value in redist_profile_params.items():
                if hasattr(existing_redist_profile, key):
                    setattr(existing_redist_profile, key, value)

            existing_redist_profile.apply()

            if not existing_redist_profile:
                return False
        except:
            logger.info(f"Redistribution profile '{name}' does not exist, creating...")
            new_params = {"name": name}
            new_params.update(redist_profile_params)
            new_redist_profile = network.RedistributionProfile(**new_params)
            virtual_router.add(new_redist_profile)
            new_redist_profile.create()
            self.created_objects.append(('redist_profile', new_redist_profile.name))

            if not new_redist_profile:
                return False
        
        return True
                
    def network_operation(self, cfg_data) -> bool:
        try:
            for object_type, objects in cfg_data.items():
                if object_type == 'layer3_subinterfaces':
                    for obj in objects:
                        parent_interface_name = obj.get('parent_interface_name')
                        #parent_exists, parent_interface = self.check_parent_interface_exists(parent_interface_name)
                                   
                        #if not parent_exists:
                        parent_interface = self.create_parent_interface(parent_interface_name, 'layer3')

                        if not parent_interface:
                            return False

                        for intf in obj['subinterfaces']:
                            intf_params = {k: v for k, v in intf.items() if v}
                            subinterface = self.create_subinterface(parent_interface, intf_params)
                            if not subinterface:
                                return False

                if object_type == 'zones':
                    for zn in objects:
                        zone_name = zn.get('name')
                        zone_params = {k: v for k, v in zn.items() if k != 'name'}

                        zone = self.create_zone(zone_name, zone_params)


                if object_type == 'virtual_routers':
                    for vr in objects:
                        virtual_router_name = vr.get('virtual_router_name')
                        virtual_router_interface = vr.get('interface')
                        redistribution_profiles = vr.get("redistribution_profiles", [])
                        static_routes = vr.get("static_routes", [])

                        virtual_router = self.create_virtual_router(virtual_router_name, virtual_router_interface)

                        if virtual_router:

                            if redistribution_profiles:
                                for redist in redistribution_profiles:
                                    redist_profile_name = redist.get('name')
                                    redist_profile_params = {k: v for k, v in redist.items() if k != 'name'}
                                    redist_profile = self.create_redist_profile(virtual_router, redist_profile_name, redist_profile_params)

                            if static_routes:
                                for route in static_routes:
                                    static_route_name = route.get('name')
                                    static_route_params = {k: v for k, v in route.items() if k != 'name'}
                                    static_route = self.create_static_route(virtual_router, static_route_name, static_route_params)

            
            # Commit changes if requested
            if self.commit_changes:
                logger.info("Committing changes...")
                self.fw.commit(admins=[self.username], sync=True)
                logger.info("Commit completed successfully")
            else:
                logger.info("Updated candidate configuration. Changes not committed")

            self.created_objects = list(set(self.created_objects))
            self.existing_objects = list(set(self.existing_objects))
            if self.created_objects:
                logger.info("Created objects:")
                logger.info("=" * 16)
                for obj in self.created_objects:
                    logger.info(f"✓ {obj}")

            if self.existing_objects:
                logger.info("Existing objects:")
                logger.info("=" * 17)
                for obj in self.existing_objects:
                    logger.info(f"✓ {obj}")
            
            return True
            
        except Exception as e:
            logger.error(f"Configuration failed: {e}")
            return False


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
        description="Create/delete/list objects in PA-NGFW"
    )
    
    # Common arguments
    parser.add_argument("--hostname", "-H", required=True,
                        help="PA NGFW hostname or IP address")
    parser.add_argument("--username", "-u", type=str, required=True,
                        help="PA NGFW admin username")
    parser.add_argument("--file", "-f", type=str, required=True,
                        help="Object configuration JSON file")
    parser.add_argument("--commit", action='store_true',
                            help="Enable commit")
    # Authentication arguments (either apikey or username/password)
    auth = parser.add_mutually_exclusive_group(required=False)
    auth.add_argument("--password", "-p", action=Password, nargs='?', dest='passwd',
                        help="PA NGFW admin password")
    auth.add_argument("--apikey", "-a", type=str,
                        help="PA NGFW API key")

    return parser.parse_args()

def get_secret(vault, vaultpath):
    from encryption import CredentialManager
    manager = CredentialManager(vault, vaultpath)
    credentails = manager.decrypt()
    return credentails


def main():

    args = parse_arguments()
    basePath = Path.home() / 'pyenv3.13' / 'panos' / 'pano_project'
    filepath = f"{basePath}/config/{args.file}"

    PA_HOST = args.hostname
    API_KEY = args.apikey
    USERNAME = args.username
    PASSWORD = args.passwd
    COMMIT = args.commit
    VAULT = "panos_secrets.bin"
    vaultpath = Path.home() / 'pyenv3.13' / 'secrets'
    objects_data = {}

    # Get object data
    if os.path.isfile(filepath):
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
        VSYS = data.get('vsys', None)
        objects_data = {k: v for k, v in data.items() if k != 'vsys'}
    else:
        logger.error("Failed to open configuration file.")
        sys.exit()
    
    if objects_data:
        if API_KEY:
            manager = PANetworkManager(
                hostname=PA_HOST,
                api_key=API_KEY,
                vsys=VSYS,
                commit_changes=COMMIT
            )
        elif not API_KEY and not USERNAME:
            credentails = get_secret(VAULT, vaultpath)
            API_KEY = credentails.get("pano_apikey")
            manager = PANetworkManager(
                hostname=PA_HOST,
                api_key=API_KEY,
                vsys=VSYS,
                commit_changes=COMMIT
            )
        elif USERNAME:
            if not PASSWORD:
                credentails = get_secret(VAULT, vaultpath)
                PASSWORD = credentails.get(USERNAME)
            manager = PANetworkManager(
                hostname=PA_HOST,
                username=USERNAME,
                password=PASSWORD,
                vsys=VSYS,
                commit_changes=COMMIT
            )
        else:
            logger.error("Missing parameters required to connect PA-NGFW")

        
        # Configure interface and routing
        success = manager.network_operation(objects_data)
    
    if success:
        print("Configuration completed successfully!")
    else:
        print("Configuration failed.")


if __name__ == "__main__":
    main()
