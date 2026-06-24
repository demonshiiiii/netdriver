#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Load and execute config-driven discovery parse rules."""

from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path
from typing import TypeAlias

import yaml
from pydantic import BaseModel, ConfigDict, Field

from netdriver_core.log import logman
from netdriver_textfsm import TextFSMParser

log = logman.logger

DiscoveryFieldMap: TypeAlias = dict[str, str]
SUPPORTED_DISCOVERY_FIELDS = frozenset(
    {
        "hostname",
        "vendor",
        "model",
        "version",
        "device_type",
        "serial_number",
    }
)

_AGENT_CONFIG_ENV_VAR = "NETDRIVER_AGENT_CONFIG"
_SNMP_PARSE_RULES_ENV_VAR = "NETDRIVER_DISCOVERY_SNMP_PARSE_RULES"
_SSH_PARSE_RULES_ENV_VAR = "NETDRIVER_DISCOVERY_SSH_PARSE_RULES"


class SnmpParseRule(BaseModel):
    """A single SNMP discovery parse rule."""

    model_config = ConfigDict(extra="forbid")

    oid: str
    template: str


class SshParseRule(BaseModel):
    """A single SSH discovery parse rule."""

    model_config = ConfigDict(extra="forbid")

    command: str
    template: str


class _SnmpRuleSet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rules: list[SnmpParseRule] = Field(default_factory=list)


def reset_parse_rule_cache() -> None:
    """Reset cached parse-rule configuration."""
    _load_snmp_rule_sets.cache_clear()
    _load_ssh_rule_sets.cache_clear()


def normalize_discovery_field_name(name: str) -> str:
    """Normalize TextFSM value names into canonical discovery field keys."""
    normalized = re.sub(r"[\s\-]+", "_", name.strip().lower())
    normalized = re.sub(r"_+", "_", normalized)
    return normalized.strip("_")


def parse_discovery_template(template: str, text: str) -> DiscoveryFieldMap:
    """Parse a TextFSM template and keep the first non-empty supported fields."""
    rows = TextFSMParser(template).parse(text or "")
    parsed_fields: DiscoveryFieldMap = {}

    for row in rows:
        if not isinstance(row, dict):
            continue
        for field_name, raw_value in row.items():
            normalized_field = normalize_discovery_field_name(str(field_name))
            if normalized_field not in SUPPORTED_DISCOVERY_FIELDS:
                continue

            normalized_value = _normalize_textfsm_value(raw_value)
            if normalized_value and not parsed_fields.get(normalized_field):
                parsed_fields[normalized_field] = normalized_value

    return parsed_fields


def get_snmp_parse_rules(vendor_key: str) -> list[SnmpParseRule]:
    """Return SNMP parse rules for a vendor key."""
    return _load_snmp_rule_sets().get(_normalize_vendor_key(vendor_key), [])


def get_ssh_parse_rules(vendor_key: str) -> SshParseRule:
    """Return SSH parse rules for a vendor key."""
    return _load_ssh_rule_sets().get(_normalize_vendor_key(vendor_key), None)


@lru_cache(maxsize=1)
def _load_snmp_rule_sets() -> dict[str, list[SnmpParseRule]]:
    """Load SNMP parse rules from YAML."""
    config_text, config_source = _load_config_text(env_var=_SNMP_PARSE_RULES_ENV_VAR, default_name="snmp_parse_rules.yml")
    if not config_text:
        return {}

    raw_config = yaml.safe_load(config_text)
    if raw_config is None:
        raw_config = {}
    if not isinstance(raw_config, dict):
        raise ValueError(f"invalid discovery parse rule format from {config_source}")

    normalized_rules: dict[str, list[SnmpParseRule]] = {}
    for vendor_key, raw_ruleset in raw_config.items():
        normalized_vendor_key = _normalize_vendor_key(str(vendor_key))
        if not normalized_vendor_key:
            raise ValueError(f"vendor key must not be empty in {config_source}")
        ruleset = _SnmpRuleSet.model_validate(raw_ruleset)
        normalized_rules[normalized_vendor_key] = ruleset.rules

    log.debug(
        f"Loaded discovery parse rules from {config_source} "
        f"with {len(normalized_rules)} vendor entries"
    )
    return normalized_rules


@lru_cache(maxsize=1)
def _load_ssh_rule_sets() -> dict[str, SshParseRule]:
    """Load SSH parse rules from YAML."""
    config_text, config_source = _load_config_text(env_var=_SSH_PARSE_RULES_ENV_VAR, default_name="ssh_parse_rules.yml")
    if not config_text:
        return {}

    raw_config = yaml.safe_load(config_text)
    if raw_config is None:
        raw_config = {}
    if not isinstance(raw_config, dict):
        raise ValueError(f"invalid discovery parse rule format from {config_source}")

    normalized_rules: dict[str, SshParseRule] = {}
    for vendor_key, raw_ruleset in raw_config.items():
        normalized_vendor_key = _normalize_vendor_key(str(vendor_key))
        if not normalized_vendor_key:
            raise ValueError(f"vendor key must not be empty in {config_source}")
        ruleset = SshParseRule.model_validate(raw_ruleset)
        normalized_rules[normalized_vendor_key] = ruleset

    log.debug(
        f"Loaded discovery parse rules from {config_source} "
        f"with {len(normalized_rules)} vendor entries"
    )
    return normalized_rules


def _load_config_text(*, env_var: str, default_name: str) -> tuple[str, str]:
    for candidate in _iter_candidate_paths(env_var=env_var, default_name=default_name):
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8"), str(candidate)

    explicit_path = os.getenv(env_var)
    if explicit_path:
        log.warning("Discovery parse rule file '%s' not found", explicit_path)

    return "", ""


def _iter_candidate_paths(*, env_var: str, default_name: str) -> list[Path]:
    candidates: list[Path] = []
    explicit_path = os.getenv(env_var)
    if explicit_path:
        candidates.append(Path(explicit_path).expanduser())

    agent_config_path = os.getenv(_AGENT_CONFIG_ENV_VAR)
    if agent_config_path:
        candidates.append(Path(agent_config_path).expanduser().parent / default_name)

    candidates.append(Path("config/agent") / default_name)
    return candidates


def _normalize_vendor_key(vendor_key: str | None) -> str:
    return vendor_key.strip().lower() if vendor_key else ""


def _normalize_textfsm_value(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        normalized_items = [str(item).strip() for item in value if str(item).strip()]
        return "\n".join(normalized_items)
    return str(value).strip()
