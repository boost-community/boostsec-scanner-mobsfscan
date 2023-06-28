"""Exports a template for Rules DB from mobsfscan rules."""
import os
import re
from pathlib import Path
from pprint import pprint
from typing import Any, Generator

import yaml

CWE_REGEXP = re.compile(r"\bcwe-(\d{1,4})\b:(.*)", re.IGNORECASE)


def is_mobsfscan_rules_file(yaml_dict: dict[str, Any]) -> bool:
    """Tells if dict looks like a mobsfscan rule."""
    return bool("rules" in yaml_dict)


def is_security_rule(rule: dict[str, Any]) -> bool:
    """Tell if dict looks is a mobsfscan security rule."""
    return bool(rule.get("metadata", {}).get("category", "") == "security")


def get_cwe_ids_list(rule: dict[str, Any]) -> list[str]:
    """Get CWE IDs list from the rule."""
    cwe = rule.get("metadata", {}).get("cwe", [])
    cwe_list = cwe if isinstance(cwe, list) else [cwe]
    return [
        f"CWE-{y.group(1).lstrip('0')}"
        for y in (CWE_REGEXP.search(x) for x in cwe_list)
        if y is not None
    ]


def get_cwe_with_details(rule: dict[str, Any]) -> dict[str, str]:
    """Get list of CWE with details."""
    cwe = rule.get("metadata", {}).get("cwe", [])
    cwe_list = cwe if isinstance(cwe, list) else [cwe]
    return {
        f"CWE-{y.group(1).lstrip('0')}": y.group(2).strip()
        for y in (CWE_REGEXP.search(x) for x in cwe_list)
        if y is not None
    }


def extract_rules_from_rule_file(
    full_path: Path, relative_path: Path
) -> Generator[dict[str, Any], None, None]:
    """Extract rules from file."""
    if full_path.suffix not in [".yaml", ".yml"]:
        return None

    with open(full_path, "r") as f:
        try:
            yaml_dict = yaml.safe_load(f)
            if not is_mobsfscan_rules_file(yaml_dict):
                return None
            for rule in yaml_dict["rules"]:
                if not is_security_rule(rule):
                    continue
                yield {
                    "id": f"{relative_path}:{rule['id']}",
                    "cwe": sorted(get_cwe_ids_list(rule)),
                    "cwe_details": get_cwe_with_details(rule),
                }
        except yaml.YAMLError:
            print(f"Error parsing rule {relative_path}")


def dump_yaml_to_file(d: dict[Any, Any], directory: Path, file_name: str) -> None:
    """Dump to YAML file."""
    directory.mkdir(parents=True, exist_ok=True)
    with open(directory / file_name, "w") as f:
        yaml.safe_dump(d, f, indent=2)


def generate_rules_db_stubs(  # noqa[C901]
    mobsfscan_rules_path: Path,
) -> None:
    """Generate rules DB stubs."""
    rules: dict[str, Any] = {}
    rules_grouped_by_cwe: dict[str, Any] = {}
    for root, dirs, files in os.walk(mobsfscan_rules_path):
        if mobsfscan_rules_path.samefile(root):
            dirs.remove("stats")
            dirs.remove(".git")
            continue
        for file in files:
            for rule in extract_rules_from_rule_file(
                Path(root) / file, Path(root).relative_to(mobsfscan_rules_path) / file
            ):
                rules[rule["id"]] = {
                    "cwe": rule["cwe"],
                    "cwe_details": rule["cwe_details"],
                }
                for cwe in rule["cwe"]:
                    if cwe not in rules_grouped_by_cwe:
                        rules_grouped_by_cwe[cwe] = {"count": 0, "rules": []}
                    group = rules_grouped_by_cwe[cwe]
                    group["count"] += 1
                    group["rules"].append(rule)

    frequently_used_cwe: dict[str, str] = {}
    for _, rule in rules.items():
        for cwe in rule["cwe"]:
            if rules_grouped_by_cwe[cwe]["count"] >= 4:
                frequently_used_cwe[cwe] = f"{cwe} - {rule['cwe_details'][cwe]}"
                break

    rules_db = {
        "rules": {
            cwe_id: {
                "categories": [
                    "ALL",
                    "cwe-top-25",  # TODO: Add conditionally
                    cwe_id.lower(),  # Synchronize with Categories DB
                ],
                "driver": "mobsfscan",
                "group": "CWE Top 25",
                "name": cwe_id,
                "pretty_name": cwe_with_name,
                "description": "Lorem_ipsum",
                "ref": "https://github.com/MobSF/mobsfscan",
            }
            for cwe_id, cwe_with_name in frequently_used_cwe.items()
        }
    }
    dump_yaml_to_file(rules_db, Path("stubs"), "rules_db.yaml")

    pprint(
        {
            cwe_id: {
                "cwe_id": cwe_id,
                "cwe_title": cwe_with_name,
                "severity": "BoostFindingSeverity.NOT_SET",
                "confidence": "BoostFindingConfidence.NOT_SET",
            }
            for cwe_id, cwe_with_name in frequently_used_cwe.items()
        },
        indent=2,
    )


if __name__ == "__main__":
    mobsfscan_rules_path = Path.home() / "sandbox" / "mobsfscan-rules"
    generate_rules_db_stubs(mobsfscan_rules_path)
