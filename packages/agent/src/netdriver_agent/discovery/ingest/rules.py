#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Load and apply discovery ingest mappings from YAML."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import TypeAlias

import yaml
from pydantic import BaseModel, ConfigDict, Field

from netdriver_core.log import logman

log = logman.logger

IngestFieldMap: TypeAlias = dict[str, str | None]
SUPPORTED_INGEST_FIELDS = frozenset({"vendor", "model", "version", "device_type"})

_AGENT_CONFIG_ENV_VAR = "NETDRIVER_AGENT_CONFIG"
_INGEST_RULES_ENV_VAR = "NETDRIVER_DISCOVERY_INGEST_RULES"


class IngestRule(BaseModel):
    """A single ingest mapping rule."""

    model_config = ConfigDict(extra="forbid")

    source: str
    target: str
    enabled: bool = True


@lru_cache(maxsize=1)
def get_ingest_rules() -> dict[str, list[IngestRule]]:
    """Load ingest rules keyed by field name."""
    config_text, config_source = _load_config_text()
    if not config_text:
        return {}

    raw_config = yaml.safe_load(config_text)
    if raw_config is None:
        raw_config = {}
    if not isinstance(raw_config, dict):
        raise ValueError(f"invalid discovery ingest rule format from {config_source}")

    normalized_rules: dict[str, list[IngestRule]] = {}
    for field_name, raw_rules in raw_config.items():
        normalized_field = _normalize_field_name(str(field_name))
        if normalized_field not in SUPPORTED_INGEST_FIELDS:
            raise ValueError(
                f"unsupported discovery ingest field {field_name!r} in {config_source}"
            )
        if not isinstance(raw_rules, list):
            raise ValueError(
                f"discovery ingest rules for field {field_name!r} must be a list"
            )

        rules = [IngestRule.model_validate(item) for item in raw_rules]
        normalized_rules[normalized_field] = rules

    log.debug(
        f"Loaded discovery ingest rules from {config_source} "
        f"with {len(normalized_rules)} field entries"
    )
    return normalized_rules


def reset_ingest_rule_cache() -> None:
    """Reset cached ingest rule configuration."""
    get_ingest_rules.cache_clear()


def apply_ingest_rules(values: IngestFieldMap) -> IngestFieldMap:
    """Apply case-insensitive exact-match ingest mappings to discovery fields."""
    rules_by_field = get_ingest_rules()
    normalized_values: IngestFieldMap = {}

    for field_name in SUPPORTED_INGEST_FIELDS:
        source_value = _normalize_optional_text(values.get(field_name))
        normalized_values[field_name] = _apply_field_rules(
            source_value,
            rules_by_field.get(field_name, []),
        )

    return normalized_values


def _apply_field_rules(
    value: str | None,
    rules: list[IngestRule],
) -> str | None:
    if value is None:
        return None
    for rule in rules:
        if not rule.enabled:
            continue
        source = _normalize_optional_text(rule.source)
        target = _normalize_optional_text(rule.target)
        if not source or not target:
            continue
        if value.casefold() == source.casefold():
            return target
    return value


def _load_config_text() -> tuple[str, str]:
    for candidate in _iter_candidate_paths():
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8"), str(candidate)

    explicit_path = os.getenv(_INGEST_RULES_ENV_VAR)
    if explicit_path:
        log.warning("Discovery ingest rule file '%s' not found", explicit_path)

    return "", ""


def _iter_candidate_paths() -> list[Path]:
    candidates: list[Path] = []
    explicit_path = os.getenv(_INGEST_RULES_ENV_VAR)
    if explicit_path:
        candidates.append(Path(explicit_path).expanduser())

    agent_config_path = os.getenv(_AGENT_CONFIG_ENV_VAR)
    if agent_config_path:
        candidates.append(
            Path(agent_config_path).expanduser().parent / "discovery_ingest_rules.yml"
        )

    candidates.append(Path("config/agent/discovery_ingest_rules.yml"))
    return candidates


def _normalize_field_name(field_name: str) -> str:
    return field_name.strip().lower()


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    trimmed = value.strip()
    return trimmed or None
