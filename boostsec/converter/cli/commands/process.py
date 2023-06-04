"""Process sarif."""
import re
import sys
from pathlib import Path
from typing import Optional

import typer
from pydantic import ValidationError

from boostsec.converter.sarif.base import ReportingDescriptor, SarifLog
from boostsec.converter.sarif.mobsfscan_sast import (
    CWE_ALLOW_LIST,
    DEFAULT_RULE_KEY,
    MobsfscanCweSastTaxa,
    append_sast_taxonomy,
)

app = typer.Typer(
    add_completion=False,
)

path_arg = typer.Argument(
    "-",
    allow_dash=True,
    exists=True,
    file_okay=True,
    dir_okay=False,
    writable=False,
    readable=True,
    resolve_path=True,
    help="Path of the mobsfscan SARIF file.",
)


@app.callback(invoke_without_command=True)
def process(path: Path = path_arg) -> None:
    """Process a mobsfscan SARIF document from stdin."""
    document: str

    if path == Path("-"):
        document = sys.stdin.read().strip()
    else:
        document = path.read_text()

    try:
        sarif_log = process_mobsfscan_sarif(document)
    except ValidationError as ve:
        typer.echo(f"unsupported JSON document, {ve}", err=True)
        typer.echo(document, err=True)
        raise typer.Exit(1) from None

    typer.echo(sarif_log.json(indent=2))


MOBSFSCAN_RULE_TAG_CWE_REGEXP = re.compile(r"\bcwe-(\d{1,5})\b", re.IGNORECASE)


def process_mobsfscan_sarif(document: str) -> SarifLog:
    """Process a mobsfscan json document."""
    sarif_log = SarifLog.parse_raw(document)
    run = sarif_log.runs[0]

    rules = run.tool.driver.rules if run.tool.driver.rules else []
    results = run.results if run.results else []

    rules_map: dict[str, ReportingDescriptor] = {rule.id: rule for rule in rules}
    rule_to_cwe_memo: dict[str, Optional[str]] = {}
    rules_idxs: dict[str, int] = {}

    for idx, rule in enumerate(rules):
        rule_id: str = rule.id
        rules_idxs[rule_id] = idx
        mapped_rule = rules_map[rule_id]
        # extract and memoize CWE from original rule
        memoize_cwe_for_rule(mapped_rule, rule_to_cwe_memo)
        # remove unwanted fields
        cleanup(rule)

    used_rules: set[str] = set()
    used_mapped_rules: set[MobsfscanCweSastTaxa] = set()

    for result in results:
        assert result.ruleId  # noqa S101 # type hint

        rule_id = result.ruleId
        used_rules.add(rule_id)

        # retrieve the CWE and related taxa
        cwe_id = rule_to_cwe_memo.get(rule_id, DEFAULT_RULE_KEY)
        taxa = MobsfscanCweSastTaxa.find_taxa_by_cwe_id(cwe_id)
        used_mapped_rules.add(taxa)

        # populate needed fields in rule
        rule = rules_map[rule_id]
        rule.relationships = [taxa.as_relationship()]
        result.taxa = [taxa.as_reference()]

    for rule in reversed(rules):
        if rule.id not in used_rules:
            del rules[rules_idxs[rule.id]]

    append_sast_taxonomy(run, used_mapped_rules)

    return sarif_log


def memoize_cwe_for_rule(
    rule: ReportingDescriptor, memo: dict[str, Optional[str]]
) -> None:
    """Memoizes the allowed CWE, if any for a given rule."""
    if not (rule.properties and rule.properties.tags):
        memo[rule.id] = DEFAULT_RULE_KEY
        return

    rule_cwe_list = [
        cwe_id
        for cwe_id in (
            f"CWE-{raw_cwe.group(1).lstrip('0')}"
            for raw_cwe in (
                MOBSFSCAN_RULE_TAG_CWE_REGEXP.search(tag) for tag in rule.properties.tags
            )
            if raw_cwe is not None
        )
        if cwe_id in CWE_ALLOW_LIST
    ]
    memo[rule.id] = rule_cwe_list[0] if rule_cwe_list else DEFAULT_RULE_KEY


FIELDS_TO_KEEP = ["id", "relationships"]


def cleanup(rule: ReportingDescriptor) -> None:
    """Remove all unnecessary fields."""
    for key in rule.dict().keys():
        if key not in FIELDS_TO_KEEP:
            rule.__delattr__(key)
