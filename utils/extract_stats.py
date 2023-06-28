"""Extracts statistics about mobsfscan-rules to JSON files."""
import json
import os
import re
from pathlib import Path
from typing import Any, Generator

import yaml

CWE_REGEXP = re.compile(r"\bcwe-(\d{1,4})\b", re.IGNORECASE)


def is_mobsfscan_rules_file(yaml_dict: dict[str, Any]) -> bool:
    """Tells if dict looks like a mobsfscan rule."""
    return bool("rules" in yaml_dict)


def is_security_rule(rule: dict[str, Any]) -> bool:
    """Tells if dict looks is a mobsfscan security rule."""
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


def extract_rules_from_rule_file(
    full_path: Path, relative_path: Path
) -> Generator[dict[str, Any], None, None]:
    """Extract rules from rule file."""
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
                }
        except yaml.YAMLError:
            print(f"Error parsing rule {relative_path}")


def dump_json_to_file(d: Any, file_name: str) -> None:
    """Dump any struct to JSON file."""
    Path("stats").mkdir(parents=True, exist_ok=True)
    with open(Path("stats") / file_name, "w") as f:
        json.dump(d, f, indent=2)


def extract_rules(mobsfscan_rules_path: Path) -> None:  # noqa[C901]
    """Dump statistics as JSON."""
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
                rules[rule["id"]] = {"cwe": rule["cwe"]}
                for cwe in rule["cwe"]:
                    if cwe not in rules_grouped_by_cwe:
                        rules_grouped_by_cwe[cwe] = {"count": 0, "rules": []}
                    group = rules_grouped_by_cwe[cwe]
                    group["count"] += 1
                    group["rules"].append(rule)

    dump_json_to_file(rules, "rules.json")
    dump_json_to_file(
        dict(filter(lambda elem: len(elem[1]["cwe"]) > 1, rules.items())),
        "rules_with_multiple_cwe.json",
    )
    dump_json_to_file(
        {
            rule_id: rule_details
            for rule_id, rule_details in rules.items()
            if len(rule_details["cwe"]) > 1
        },
        "rules_with_multiple_cwe.json",
    )

    sorted_rules_grouped_by_cwe = dict(
        sorted(
            rules_grouped_by_cwe.items(),
            key=lambda item: int(item[1]["count"]),
            reverse=True,
        )
    )
    dump_json_to_file(sorted_rules_grouped_by_cwe, "rules_grouped_by_cwe.json")

    rarely_used_cwe: set[str] = set()
    for cwe, cwe_group in sorted_rules_grouped_by_cwe.items():
        if cwe_group["count"] == 1:
            for rule in cwe_group["rules"]:
                if len(rule["cwe"]) == 1:
                    rarely_used_cwe.add(cwe)
                    break
    dump_json_to_file(list(rarely_used_cwe), "rarely_used_cwe.json")

    rules_that_have_a_single_rare_cwe: dict[str, str] = {}
    for rule_id, rule in rules.items():
        if len(rule["cwe"]) == 1:
            cwe = rule["cwe"][0]
            if sorted_rules_grouped_by_cwe[cwe]["count"] <= 2:
                rules_that_have_a_single_rare_cwe[rule_id] = cwe
    dump_json_to_file(
        rules_that_have_a_single_rare_cwe, "rules_that_have_a_single_rare_cwe.json"
    )

    cwes_with_more_than_x_occurences: list[str] = []
    for cwe, cwe_group in sorted_rules_grouped_by_cwe.items():
        if cwe_group["count"] > 2:
            cwes_with_more_than_x_occurences.append(cwe)
    dump_json_to_file(
        cwes_with_more_than_x_occurences, "cwes_with_more_than_x_occurences.json"
    )

    rules_with_frequently_used_cwe: dict[str, str] = {}
    for rule_id, rule in rules.items():
        for cwe in rule["cwe"]:
            if sorted_rules_grouped_by_cwe[cwe]["count"] >= 4:
                rules_with_frequently_used_cwe[rule_id] = cwe
                break
    dump_json_to_file(
        rules_with_frequently_used_cwe, "rules_with_frequently_used_cwe.json"
    )
    dump_json_to_file(
        list(set([v for k, v in rules_with_frequently_used_cwe.items()])),  # noqa[C403]
        "frequently_used_cwe.json",
    )

    security_rules_with_no_cwe: list[str] = []
    for rule_id, rule in rules.items():
        if len(rule["cwe"]) == 0:
            security_rules_with_no_cwe.append(rule_id)
    dump_json_to_file(security_rules_with_no_cwe, "security_rules_with_no_cwe.json")


if __name__ == "__main__":
    mobsfscan_rules_path = Path.home() / "sandbox" / "mobsfscan-rules"
    extract_rules(mobsfscan_rules_path)
