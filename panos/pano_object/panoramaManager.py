#!/usr/bin/env python3
"""
Manage security rules and their referenced objects in Panorama device groups
using the pan-os-python SDK.
"""

import argparse
import getpass
import json
import logging
import os
import re
import sys
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional

from panos.objects import (
    AddressGroup,
    AddressObject,
    CustomUrlCategory,
    Edl,
    ServiceGroup,
    ServiceObject,
)
from panos.panorama import DeviceGroup, Panorama
from panos.policies import PostRulebase, PreRulebase, RuleAuditComment, SecurityRule

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

AUDIT_COMMENT_RE = re.compile(r"^(CHG|RITM|INC)[0-9]{7}")

# Registry of supported object types -> pan-os-python class
OBJECT_TYPES = {
    "address_object": AddressObject,
    "address_group": AddressGroup,
    "service_object": ServiceObject,
    "service_group": ServiceGroup,
    "url_category": CustomUrlCategory,
    "external_dynamic_list": Edl,
}

# Registry of supported rulebases -> pan-os-python class
RULEBASE_TYPES = {
    "pre-rulebase": PreRulebase,
    "post-rulebase": PostRulebase,
}


def _log_section(message: str) -> None:
    logger.info("=" * 60)
    logger.info(message)
    logger.info("=" * 60)


class OperationType(Enum):
    CREATE = "create"
    DELETE = "delete"
    LIST = "list"
    MOVE = "move"

    @classmethod
    def from_string(cls, value: str) -> "OperationType":
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(
                f"Invalid operation: {value}. Must be 'create', 'delete', 'list', or 'move'"
            )


class ObjectType(Enum):
    ADDRESS = "address_object"
    ADDRESS_GROUP = "address_group"
    SERVICE = "service_object"
    SERVICE_GROUP = "service_group"
    URL_CATEGORY = "url_category"
    EDL = "external_dynamic_list"

    @classmethod
    def from_string(cls, value: str) -> "ObjectType":
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(f"Invalid object type: {value}.")


class RuleType(Enum):
    PRE_RULE = "pre-rulebase"
    POST_RULE = "post-rulebase"

    @classmethod
    def from_string(cls, value: str) -> "RuleType":
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(
                f"Invalid rulebase type: {value}. Must be 'pre-rulebase' or 'post-rulebase'"
            )


class PanoramaManager:
    """Manage security rules and objects in a Panorama rulebase."""

    def __init__(
        self,
        hostname: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_key: Optional[str] = None,
        audit_comment: Optional[str] = None,
        commit_changes: bool = False,
        **kwargs,
    ):
        self.hostname = hostname
        self.username = username
        self.audit_comment = audit_comment
        self.commit_changes = commit_changes
        self.scope = None
        self.object_type = None
        self.rulebase = None

        if api_key:
            self.panorama = Panorama(hostname, api_key=api_key)
        elif username and password:
            self.panorama = Panorama(
                hostname, api_username=username, api_password=password
            )
        else:
            raise ValueError("Either api_key or username/password must be provided")

    # ------------------------------------------------------------------
    # Lookup / scope helpers
    # ------------------------------------------------------------------
    def _get_device_group(self, device_group_name: str) -> Optional[DeviceGroup]:
        for dg in DeviceGroup.refreshall(self.panorama):
            if dg.name == device_group_name:
                return dg
        return None

    def _get_existing_object(self, object_type: type, name: str):
        for obj in object_type.refreshall(self.scope):
            if obj.name == name:
                return obj
        return None

    def _get_existing_rule(self, rule_name: str) -> Optional[SecurityRule]:
        self.scope.add(self.rulebase)
        for rule in SecurityRule.refreshall(self.rulebase):
            if rule.name == rule_name:
                return rule
        return None

    def _set_scope(self, device_group_name: str) -> bool:
        if device_group_name == "Shared":
            self.scope = self.panorama
            return True
        device_group = self._get_device_group(device_group_name)
        if not device_group:
            logger.error(f"Error: '{device_group_name}' does not exist")
            return False
        self.scope = device_group
        return True

    # ------------------------------------------------------------------
    # Generic object CRUD (replaces 12 near-identical methods)
    # ------------------------------------------------------------------
    def _upsert(self, object_type: type, name: str, params: Dict) -> bool:
        try:
            existing = self._get_existing_object(object_type, name)
            if existing:
                logger.info(f"{object_type.__name__} '{name}' already exists, updating...")
                for key, value in params.items():
                    if hasattr(existing, key):
                        setattr(existing, key, value)
                existing.apply()
                return bool(existing)

            logger.info(f"{object_type.__name__} '{name}' does not exist, creating...")
            new_obj = object_type(name=name, **params)
            self.scope.add(new_obj)
            new_obj.create()
            return bool(new_obj)
        except Exception as e:
            logger.error(f"Error managing {object_type.__name__} '{name}': {e}")
            return False

    def _delete_object(self, object_type: type, name: str) -> bool:
        try:
            existing = self._get_existing_object(object_type, name)
            if existing:
                existing.delete()
                logger.info(f"Deleted {object_type.__name__} '{name}'")
                return True
            logger.warning(f"{object_type.__name__} '{name}' not found")
            return False
        except Exception as e:
            logger.error(f"Error deleting {object_type.__name__} '{name}': {e}")
            return False

    @staticmethod
    def _normalize_object_params(object_key: str, params: Dict) -> Dict:
        """Map config-file field names to pan-os-python attribute names."""
        if object_key == "address_group":
            params = dict(params)
            if "filter_criteria" in params:
                params["dynamic_value"] = params.pop("filter_criteria")
            elif "member_names" in params:
                params["static_value"] = params.pop("member_names")
        return params

    # Thin backward-compatible wrappers ----------------------------------
    def create_or_update_url_category(self, name, params):
        return self._upsert(CustomUrlCategory, name, params)

    def delete_url_category(self, name):
        return self._delete_object(CustomUrlCategory, name)

    def create_or_update_address_object(self, name, params):
        return self._upsert(AddressObject, name, params)

    def delete_address_object(self, name):
        return self._delete_object(AddressObject, name)

    def create_or_update_address_group(self, name, params):
        return self._upsert(
            AddressGroup, name, self._normalize_object_params("address_group", params)
        )

    def delete_address_group(self, name):
        return self._delete_object(AddressGroup, name)

    def create_or_update_service_object(self, name, params):
        return self._upsert(ServiceObject, name, params)

    def delete_service_object(self, name):
        return self._delete_object(ServiceObject, name)

    def create_or_update_service_group(self, name, params):
        return self._upsert(ServiceGroup, name, params)

    def delete_service_group(self, name):
        return self._delete_object(ServiceGroup, name)

    def create_or_update_edl(self, name, params):
        return self._upsert(Edl, name, params)

    def delete_edl(self, name):
        return self._delete_object(Edl, name)

    # ------------------------------------------------------------------
    # Rule operations
    # ------------------------------------------------------------------
    def create_or_update_rule(self, rule_params: Dict) -> bool:
        rule_name = rule_params.get("name")
        existing_rule = self._get_existing_rule(rule_name)

        try:
            if existing_rule:
                logger.info(f"Rule '{rule_name}' already exists, updating...")
                for key, value in rule_params.items():
                    if key != "name" and hasattr(existing_rule, key):
                        setattr(existing_rule, key, value)
                existing_rule.apply()
                RuleAuditComment(existing_rule).update(self.audit_comment)
                logger.info(f"Rule '{rule_name}' updated successfully.")
                return True

            logger.info(f"Rule '{rule_name}' does not exist, creating...")
            self.scope.add(self.rulebase)
            new_rule = SecurityRule(**rule_params)
            self.rulebase.add(new_rule)
            new_rule.create()
            RuleAuditComment(new_rule).update(self.audit_comment)
            logger.info(f"Rule '{rule_name}' created successfully.")
            return True
        except Exception as e:
            logger.error(f"Failed to upsert rule '{rule_name}': {e}")
            return False

    def move_rule(self, rule_name: str, move_params: Dict) -> bool:
        existing_rule = self._get_existing_rule(rule_name)
        if not existing_rule:
            logger.error(f"Rule '{rule_name}' does not exist.")
            return False
        try:
            existing_rule.move(**move_params)
            logger.info(f"Rule '{rule_name}' moved successfully.")
            return True
        except Exception as e:
            logger.error(f"Failed to move rule '{rule_name}': {e}")
            return False

    def delete_rule(self, rule_name: str) -> bool:
        existing_rule = self._get_existing_rule(rule_name)
        if not existing_rule:
            logger.error(f"Rule '{rule_name}' does not exist.")
            return False
        try:
            existing_rule.delete()
            logger.info(f"Rule '{rule_name}' deleted successfully.")
            return True
        except Exception as e:
            logger.error(f"Failed to delete rule '{rule_name}': {e}")
            return False

    def list_rule(self, rule_name: str) -> bool:
        existing_rule = self._get_existing_rule(rule_name)
        if existing_rule:
            logger.info(existing_rule.about())
            return True
        return False

    # ------------------------------------------------------------------
    # Batch helpers
    # ------------------------------------------------------------------
    def _validate_audit_comment(self) -> bool:
        if not self.audit_comment:
            logger.error("Missing rule audit comment")
            return False
        if not AUDIT_COMMENT_RE.fullmatch(self.audit_comment):
            logger.error("Invalid rule audit comment")
            return False
        return True

    def _run_object_ops(
        self,
        operation: str,
        object_data: Dict,
        device_group_name: str,
        results: Dict[str, bool],
    ) -> None:
        for object_key, object_cls in OBJECT_TYPES.items():
            if object_key not in object_data:
                continue

            _log_section(
                f"{operation.capitalize()}ing {object_key}s in '{device_group_name}'"
            )
            self.object_type = object_cls

            for obj in object_data[object_key]:
                name = obj.get("name")
                if not name:
                    continue

                if operation == "create":
                    params = self._normalize_object_params(
                        object_key, {k: v for k, v in obj.items() if k != "name"}
                    )
                    success = self._upsert(object_cls, name, params)
                elif operation == "delete":
                    success = self._delete_object(object_cls, name)
                elif operation == "list":
                    existing = self._get_existing_object(object_cls, name)
                    success = existing is not None
                    if existing:
                        logger.info(existing.about())
                else:
                    continue

                results[f"{object_key}_{name}"] = success

    def _run_rule_ops(
        self,
        operation: str,
        object_data: Dict,
        device_group_name: str,
        results: Dict[str, bool],
    ) -> bool:
        """Returns False to signal early exit (e.g. bad audit comment)."""
        present = [(k, RULEBASE_TYPES[k]) for k in RULEBASE_TYPES if k in object_data]
        if not present:
            return True

        if operation == "create" and not self._validate_audit_comment():
            return False

        for rulebase_key, rulebase_cls in present:
            self.rulebase = rulebase_cls()
            _log_section(
                f"{operation.capitalize()}ing rules in '{device_group_name}'"
            )

            for rule in object_data[rulebase_key]:
                name = rule.get("name")
                if not name:
                    continue
                move_params = rule.get("move", {})

                if operation == "create":
                    rule_params = {k: v for k, v in rule.items() if k != "move" and v}
                    success = self.create_or_update_rule(rule_params)
                    if move_params:
                        success = self.move_rule(name, move_params)
                elif operation == "delete":
                    success = self.delete_rule(name)
                elif operation == "list":
                    success = self.list_rule(name)
                elif operation == "move":
                    if not move_params:
                        continue
                    success = self.move_rule(name, move_params)
                else:
                    continue

                results[f"{rulebase_key}_{name}"] = success

        return True

    def _maybe_commit(self, results: Dict[str, bool]) -> None:
        failures = [k for k, v in results.items() if v is False]
        if self.commit_changes and not failures:
            logger.info("Committing changes...")
            self.panorama.commit(admins=[self.username], sync=True)
            logger.info("Commit completed successfully")
        else:
            logger.info("Updated candidate configuration. Changes not committed")

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    def run_operation(
        self, operation: str, cfg_data: Dict[str, Any]
    ) -> Dict[str, bool]:
        results: Dict[str, bool] = {}

        try:
            op = OperationType.from_string(operation).value

            for device_group_name, object_data in cfg_data.items():
                if not self._set_scope(device_group_name):
                    return results
                if not object_data:
                    continue

                if op in ("create", "delete", "list"):
                    self._run_object_ops(op, object_data, device_group_name, results)

                if not self._run_rule_ops(
                    op, object_data, device_group_name, results
                ):
                    return results

            if op in ("create", "delete", "move") and results:
                self._maybe_commit(results)

            return results

        except Exception as e:
            logger.error(f"Error in object operation: {e}")
            return results


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def parse_arguments():
    class Password(argparse.Action):
        def __call__(self, parser, namespace, values, option_string):
            if values is None:
                values = getpass.getpass()
            setattr(namespace, self.dest, values)

    parser = argparse.ArgumentParser(
        description="Arguments to run PanoramaManager script"
    )
    parser.add_argument("--hostname", "-H", required=True,
                        help="Panorama hostname or IP address")
    parser.add_argument("--username", "-u", type=str,
                        help="Panorama admin username")
    parser.add_argument("--file", "-f", type=str,
                        help="The name of JSON configuration file")
    parser.add_argument(
        "--operation", "-o",
        choices=["create", "delete", "move", "list"],
        nargs="?", const="list", default="list",
        help="Operation modes are create, delete, move, or list. Default to 'list'",
    )

    auth = parser.add_mutually_exclusive_group(required=False)
    auth.add_argument("--password", "-p", action=Password, nargs="?", dest="passwd",
                      help="Panorama admin password")
    auth.add_argument("--apikey", "-a", type=str, help="Panorama API key")

    parser.add_argument("--audit", type=str, help="Rule audit comments")
    parser.add_argument("--commit", action="store_true", help="Commit changes")

    return parser.parse_args()


def get_secret(vault, vaultpath):
    from encryption import CredentialManager
    return CredentialManager(vault, vaultpath).decrypt()


def main():
    args = parse_arguments()
    base_path = Path.home() / "pyenv3.13" / "panos" / "pan_project"
    filepath = f"{base_path}/config/{args.file}"

    PANORAMA_HOST = args.hostname
    API_KEY = args.apikey
    USERNAME = args.username
    PASSWORD = args.passwd
    OPERATION = args.operation
    AUDIT_COMMENT = args.audit or None
    COMMIT = args.commit
    VAULT = "panos_secrets.bin"
    vaultpath = Path.home() / "pyenv3.13" / "secrets"

    if not os.path.isfile(filepath):
        logger.info("Error: Objects must be provided")
        sys.exit(0)

    with open(filepath, "r", encoding="utf-8-sig") as f:
        data = json.load(f)

    if not AUDIT_COMMENT:
        AUDIT_COMMENT = data.get("audit_comment")
    cfg_data = {k: v for k, v in data.items() if k != "audit_comment"}

    if not cfg_data:
        sys.exit(0)

    # Resolve credentials and construct the manager
    if not API_KEY and not USERNAME:
        API_KEY = get_secret(VAULT, vaultpath).get("pano_apikey")
    if USERNAME and not PASSWORD:
        PASSWORD = get_secret(VAULT, vaultpath).get(USERNAME)

    manager = PanoramaManager(
        hostname=PANORAMA_HOST,
        username=USERNAME,
        password=PASSWORD,
        api_key=API_KEY,
        audit_comment=AUDIT_COMMENT,
        commit_changes=COMMIT,
    )

    results = manager.run_operation(OPERATION, cfg_data)

    logger.info("Operation results:")
    for obj_name, success in results.items():
        logger.info(f"  {'✓' if success else '✗'} {obj_name}")

    _log_section("Operations completed successfully!")


if __name__ == "__main__":
    main()
