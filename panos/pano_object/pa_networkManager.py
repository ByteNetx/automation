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
            
        """
        try:
            if parent_interface_name.startswith("ae"):
                parent_interface = network.AggregateInterface(parent_interface_name, mode=mode)
            else:
                parent_interface = network.EthernetInterface(parent_interface_name, mode=mode)

            self.fw.add(parent_interface)
            parent_interface.create()
            self.created_objects.append(('Interface', parent_interface.name))
            logger.info(f"Interface {parent_interface.name} created")
            return parent_interface
            
        except PanDeviceError as e:
            logger.info(f"It failed to create interface {parent_interface_name}: {e}")
            return None

    def create_subinterface(self, parent_interface: network.Interface, intf_params: Dict) -> Optional[network.Layer3Subinterface]:

        try:
           
            if not parent_interface:
                return None

            vlan_tag = intf_params.get('vlan_tag')
            subinterface_name = f"{parent_interface.name}.{vlan_tag}"

            try:
                subinterface = network.Layer3Subinterface(subinterface_name)
                parent_interface.add(subinterface)
                subinterface.refresh(parent_interface)

                self.existing_objects.append(('layer3_subinterface', subinterface.name))
                logger.info(f"Layer3 subinterface {subinterface.name} already exists, updating...")

                # Update existing subinterface
                subinterface.ip = intf_params.get('ip')
                if intf_params.get('comment'):
                    subinterface.comment = intf_params.get('comment')
                if intf_params.get('management_profile'):
                    subinterface.management_profile = intf_params.get('management_profile')
                subinterface.apply()

                return subinterface
            except:
                logger.info(f"Subinterface {subinterface_name} does not exist, creating...")

                # Create the subinterface object
                subinterface = network.Layer3Subinterface(
                    name=subinterface_name,
                    tag=vlan_tag,
                    ip=intf_params.get('ip'),
                    management_profile=intf_params.get('management_profile') or None,
                    comment=intf_params.get('comment') or f"Created by PANetworkManager"
                )

                parent_interface.add(subinterface)
                
                # Apply the subinterface
                subinterface.create()
            
                self.created_objects.append(('layer3_subinterface', subinterface.name))
                logger.info(f"layer3_subinterface {subinterface.name} created")

                return subinterface
            
        except PanDeviceError as e:
            logger.error(f"Failed to create/update subinterface: {e}")
            return None

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
            logger.infor(f"Zone {zone_name} does not exist")
            return False, None

    def create_zone(self, zone_params: Dict) -> Optional[network.Zone]:
        """
        Create a zone on the firewall

        Returns:
            Optional[network.Zone]: The zone object
        """
        try:
            zone_name = zone_params.get('zone_name')
            zone_mode = zone_params.get('mode')
            zone = network.Zone(name=zone_name, mode=zone_mode)
            self.fw.add(zone)

            zone.create()
            logger.info(f"Zone {zone.name} created")
            self.created_objects.append(('zone', zone.name))
            
            return zone
            
        except PanDeviceError as e:
            logger.error(f"Failed to create zone {zone_name}: {e}")
            return None
    
    def add_interface_to_zone(
        self,
        zone: network.Zone,
        zn_interfaces: List
    ) -> bool:
        """
        Add a layer3 subinterface to a zone.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not zone:
                logger.error("Invalid zone provided")
                return False
            
            # Get current interfaces in zone
            current_interfaces = getattr(zone, 'interface', []) or []
            
            # Add new interface if not already present
            new_intfs = [i for i in zn_interfaces if i not in current_interfaces]

            if new_intfs:
                current_interfaces.extend(new_intfs)
                zone.interface = current_interfaces
                zone.apply()
                logger.info(
                    f"Interface {new_intfs} added to zone {zone.name}"
                )
            else:
                logger.info(
                    f"Interface {new_intfs} already exist in zone {zone.name}"
                )
            
            return True
            
        except PanDeviceError as e:
            logger.error(f"Failed to add interface to zone: {e}")
            return False
    
    def create_virtual_router(
        self,
        virtual_router_name: str
    ) -> Optional[network.VirtualRouter]:
        """
        Create a virtual router on the firewall.

        Returns:
            Optional[network.VirtualRouter]: The virtual router object
        """

        try:
            virtual_router = network.VirtualRouter(virtual_router_name)
            self.fw.add(virtual_router)
            virtual_router.create()
            logger.info(f"Virtual router {virtual_router.name} created")
            self.created_objects.append(('virtual_router', virtual_router.name))

            return virtual_router
            
        except PanDeviceError as e:
            logger.error(f"Failed to create virtual router {virtual_router_name}: {e}")
            return None
    
    def configure_redist_profile(
        self,
        virtual_router: network.VirtualRouter,
        redist_profile_params: Dict
    ) -> bool:
        """
        Configure redistribution profile and assign interface.

        Returns:
            Optional[network.RedistributionProfile]: The redistribution profile object
        """

        try:
            redist_profile_name = redist_profile_params.get('redist_profile_name')
            redist_filter_type = redist_profile_params.get('redist_filter_type')
            redist_filter_interface = redist_profile_params.get('redist_filter_interface')
            redist_filter_priority = redist_profile_params.get('priority', '1')
            redist_filter_action = redist_profile_params.get('action', 'redist')


            if not virtual_router:
                logger.error(f"Invalid virtual router provided")
                return None

            redist_profile = network.RedistributionProfile(redist_profile_name)
            virtual_router.add(redist_profile)

            try:
                redist_profile.refresh(virtual_router)
                logger.info(f"Redistribution profile {redist_profile.name} already exists")
                self.existing_objects.append(('redist_profile', redist_profile_name))

            except PanDeviceError:
                redist_profile.create()
                logger.info(f"Redistribution profile {redist_profile.name} created")
                self.created_objects.append(('redist_profile', redist_profile_name))

            current_interfaces = getattr(redist_profile, 'filter_interface', []) or []
            current_filter_type = getattr(redist_profile, 'filter_type', []) or []

            current_interfaces.extend(redist_filter_interface)
            redist_profile.filter_interface = current_interfaces
            current_filter_type.extend(redist_filter_type)
            redist_profile.filter_type = current_filter_type
            redist_profile.priority = redist_filter_priority
            redist_profile.action = redist_filter_action
            redist_profile.create()
            logger.info(
                f"Interface {redist_filter_interface} added to Redistribution profile {redist_profile.name}"
            )
            
            return redist_profile
            
        except PanDeviceError as e:
            logger.error(f"Failed to configure Redistribution profile: {e}")
            return None

    def add_interface_to_virtual_router(
        self,
        virtual_router: network.VirtualRouter,
        vr_interfaces: List
    ) -> bool:
        """
        Add a layer3 subinterface to a virtual router.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not virtual_router:
                logger.error("Invalid virtual router provided")
                return False

            current_interfaces = getattr(virtual_router, 'interface', []) or []
            
            # Add interface if not already present
            new_intfs = [i for i in vr_interfaces if i not in current_interfaces]

            if new_intfs:
                current_interfaces.extend(new_intfs)
                virtual_router.interface = current_interfaces
                virtual_router.create()
                logger.info(
                    f"Interfaces {new_intfs} added to virtual router {virtual_router.name}"
                )
            else:
                logger.info(
                    f"Interfaces {new_intfs} already exist in virtual router {virtual_router.name}"
                )

            return True

        except PanDeviceError as e:
            logger.error(f"Failed to add interface to virtual router: {e}")
            return False
                
    def network_operation(self, cfg_data) -> bool:
        try:
            for object_type, objects in cfg_data.items():
                if object_type == 'layer3_subinterfaces':
                    for obj in objects:
                        parent_interface_name = obj.get('parent_interface_name')
                        parent_exists, parent_interface = self.check_parent_interface_exists(parent_interface_name)
                                   
                        if not parent_exists:
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
                        zone_name = zn.get('zone_name')
                        zone_params = {k: v for k, v in zn.items() if k != 'interfaces'}
                        zone_interfaces = zn.get('interfaces')
                        zn_exists, zone = self.check_zone_exists(zone_name)
                        if not zn_exists:
                            zone = self.create_zone(zone_params)
                        if not zone:
                            return False

                        # Add interface to zone
                        if not self.add_interface_to_zone(zone, zone_interfaces):
                            return False

                if object_type == 'virtual_routers':
                    for vr in objects:
                        virtual_router_name = vr.get('virtual_router_name')
                        vr_interfaces = vr.get('interfaces')
                        vr_exists, virtual_router = self.check_virtual_router_exists(virtual_router_name)
                        if not vr_exists:
                            virtual_router = self.create_virtual_router(virtual_router_name)

                        if not virtual_router:
                            return False

                        # Add interface to virtual router
                        if not self.add_interface_to_virtual_router(virtual_router, vr_interfaces):
                            return False

                        if "redistribution_profiles" in vr:
                            for redist in vr["redistribution_profiles"]:
                                redist_profile_params = {k: v for k, v in redist.items() if v}
                                redist_profile = self.configure_redist_profile(virtual_router, redist_profile_params)
                                if not redist_profile:
                                    return False
            
            # Commit changes if requested
            if self.commit_changes:
                logger.info("Committing changes...")
                self.fw.commit(admins=[self.username], sync=True)
                logger.info("Commit completed successfully")
            else:
                logger.info("Dry-run completed. Changes not committed")

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

        
        # Configure interface and routing
        success = manager.network_operation(objects_data)
    
    if success:
        print("Configuration completed successfully!")
    else:
        print("Configuration failed.")


if __name__ == "__main__":
    main()
