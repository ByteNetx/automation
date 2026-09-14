#!/usr/bin/env python3
"""
Convert an Excel workbook describing Panorama objects/rules into a JSON file
matching the required schema.
"""

import json
import sys
from pathlib import Path

import pandas as pd


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clean(value):
    """Return None for NaN / empty strings, otherwise a stripped string."""
    if value is None:
        return None
    if isinstance(value, float) and pd.isna(value):
        return None
    text = str(value).strip()
    return text if text != "" else None


def _as_list(value):
    """Split a comma-separated cell into a trimmed list, dropping empties."""
    if value is None:
        return None
    if isinstance(value, float) and pd.isna(value):
        return None
    items = [v.strip() for v in str(value).split(",")]
    items = [v for v in items if v]
    return items or None


def read_sheet(xls, sheet_name):
    """Read a sheet as a list of dicts, with blank cells removed."""
    df = pd.read_excel(xls, sheet_name=sheet_name, dtype=str)
    rows = []
    for _, row in df.iterrows():
        record = {}
        for col, val in row.items():
            v = _clean(val)
            if v is not None:
                record[col.strip()] = v
        if record:                       # skip fully-empty rows
            rows.append(record)
    return rows


def read_sheet_optional(xls, sheet_name):
    """Return [] if the sheet does not exist."""
    try:
        return read_sheet(xls, sheet_name)
    except ValueError:
        return []

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Columns that must be converted to lists, per section
LIST_FIELDS = {
    "address_group":        {"member_names"},
    "service_group":        {"value"},
    "pre-rulebase":         {"fromzone", "tozone", "source", "destination",
                             "application", "service", "category"},
    "url_category":         {"url_value"},
    "post-rulebase":        {"fromzone", "tozone", "source", "destination",
                             "application", "service", "category"},
}

def excel_to_json(xlsx_path: Path, json_path: Path) -> dict:
    xls = pd.ExcelFile(xlsx_path)

    result = {}

    # ---- top-level audit_comment and commit ----
    df_config = pd.read_excel(xls, sheet_name='config', dtype=str)
    for r in df_config.itertuples():
        result["audit_comment"] = r.audit_comment

    # ---- Device-group container ----
    sections = ("address_object", "address_group",
                "service_object", "service_group",
                "external_dynamic_list", "url_category",
                "pre-rulebase", "post-rulebase")

    for section in sections:
        rows = read_sheet_optional(xls, section)
        if rows:
            list_fields = LIST_FIELDS.get(section, set())
            for row in rows:
                item = {}
                location = row.get('location', None)
                if not location:
                    continue
        
                if location not in result:
                    result.update({location: {}})
                if section not in result[location]:
                    result[location].update({section: []})

                cfg_data = {k: v for k, v in row.items() if k !='location'}

                for key, val in cfg_data.items():
                        if key in list_fields:
                            item[key] = _as_list(val)
                        else:
                            item[key] = val
        
                # Rulebase: nest move_location + move_ref into a "move" object
                if section == "pre-rulebase" or section == "post-rulebase":
                    loc = item.pop("move_location", None)
                    ref = item.pop("move_ref", None)
                    if loc and ref:
                        item["move"] = {"location": loc, "ref": ref}
                result[location][section].append(item)

    # ---- write ----
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=4)

    return result

if __name__ == "__main__":
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("input.xlsx")
    dst = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("output.json")

    data = excel_to_json(src, dst)
    print(f"Wrote {dst}  ({len(json.dumps(data))} bytes)")
